package org.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import java.util.Properties;
class ChatClientTest {

    @Test
    void exchangesEncryptedMessagesWithPeer() throws Exception {
        KeyPair peerKeys = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        ByteArrayOutputStream consoleOutput = new ByteArrayOutputStream();
        InputStream originalIn = System.in;
        PrintStream originalOut = System.out;
        ExecutorService executor = Executors.newSingleThreadExecutor();
        PipedInputStream consoleInput = new PipedInputStream();
        PipedOutputStream consoleWriter = new PipedOutputStream(consoleInput);
        Future<?> clientRun = null;

        try (ServerSocket fakeRelay = new ServerSocket(0)) {
            fakeRelay.setSoTimeout(5_000);
            System.setIn(consoleInput);
            System.setOut(new PrintStream(consoleOutput, true, StandardCharsets.UTF_8));

            clientRun = executor.submit(() -> {
                new ChatClient("Ana", "127.0.0.1", fakeRelay.getLocalPort()).start();
                return null;
            });
            try (Socket peer = fakeRelay.accept()) {
                peer.setSoTimeout(5_000);
                BufferedReader peerInput = new BufferedReader(
                        new InputStreamReader(peer.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter peerOutput = new PrintWriter(peer.getOutputStream(), true, StandardCharsets.UTF_8);

                String[] hello = peerInput.readLine().split("\\t", -1);
                assertEquals(3, hello.length);
                assertEquals("HELLO", hello[0]);
                String clientId = hello[1];
                PublicKey clientPublicKey = KeyFactory.getInstance("X25519")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(hello[2])));

                String peerId = "peer-1";
                peerOutput.println("PEER\t" + peerId + "\t"
                        + Base64.getEncoder().encodeToString(peerKeys.getPublic().getEncoded()));
                assertTrue(awaitOutput(consoleOutput, "[INFO] Participant " + peerId + " conectat"));

                consoleWriter.write("salut\n".getBytes(StandardCharsets.UTF_8));
                consoleWriter.flush();
                String[] message = peerInput.readLine().split("\\t", -1);
                assertEquals(5, message.length);
                assertEquals("MSG", message[0]);
                assertEquals(clientId, message[1]);
                assertEquals(peerId, message[2]);

                byte[] nonce = Base64.getDecoder().decode(message[3]);
                byte[] ciphertext = Base64.getDecoder().decode(message[4]);
                assertEquals(12, nonce.length);
                assertEquals("Ana: salut", decrypt(
                        deriveKey(peerKeys.getPrivate(), clientPublicKey, "chat message key:" + clientId),
                        nonce,
                        ciphertext));

                byte[] replyNonce = new byte[12];
                byte[] replyCiphertext = encrypt(
                        deriveKey(peerKeys.getPrivate(), clientPublicKey, "chat message key:" + peerId),
                        replyNonce,
                        "Bob: salut".getBytes(StandardCharsets.UTF_8));
                peerOutput.println("MSG\t" + peerId + "\t"
                        + Base64.getEncoder().encodeToString(replyNonce) + "\t"
                        + Base64.getEncoder().encodeToString(replyCiphertext));
                assertTrue(awaitOutput(consoleOutput, "Bob: salut"));

                consoleWriter.write("/quit\n".getBytes(StandardCharsets.UTF_8));
                consoleWriter.flush();
                consoleWriter.close();
                clientRun.get(5, TimeUnit.SECONDS);
            }
        } finally {
            consoleWriter.close();
            if (clientRun != null && !clientRun.isDone()) clientRun.cancel(true);
            executor.shutdownNow();
            System.setIn(originalIn);
            System.setOut(originalOut);
        }
    }

    private static boolean awaitOutput(ByteArrayOutputStream output, String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            synchronized (output) {
                if (output.toString(StandardCharsets.UTF_8).contains(expected)) return true;
            }
            Thread.sleep(10);
        }
        return false;
    }

    private static byte[] deriveKey(
            java.security.PrivateKey privateKey,
            PublicKey publicKey,
            String label
    ) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("CHAT_e2ee_demo_v1".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] pseudorandomKey = mac.doFinal(agreement.generateSecret());
        mac.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
        mac.update((label + "\u0001").getBytes(StandardCharsets.UTF_8));
        return mac.doFinal();
    }

    private static byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(plaintext);
    }

    private static String decrypt(byte[] key, byte[] nonce, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

}
