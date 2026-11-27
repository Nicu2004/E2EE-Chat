package org.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.southernstorm.noise.protocol.CipherStatePair;
import com.southernstorm.noise.protocol.DHState;
import com.southernstorm.noise.protocol.HandshakeState;
import com.southernstorm.noise.protocol.Noise;
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
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ChatClientTest {
    private static final String NOISE_PROTOCOL = "Noise_XX_25519_AESGCM_SHA256";

    @Test
    void exchangesNoiseEncryptedMessagesAfterCertificateHandshake(@TempDir Path home) throws Exception {
        String originalHome = System.getProperty("user.home");
        InputStream originalInput = System.in;
        PrintStream originalOutput = System.out;
        ByteArrayOutputStream consoleOutput = new ByteArrayOutputStream();
        PipedInputStream consoleInput = new PipedInputStream();
        PipedOutputStream consoleWriter = new PipedOutputStream(consoleInput);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<?> clientRun = null;

        try (ServerSocket fakeRelay = new ServerSocket(0)) {
            fakeRelay.setSoTimeout(5_000);
            System.setProperty("user.home", home.toString());
            System.setIn(consoleInput);
            System.setOut(new PrintStream(consoleOutput, true, StandardCharsets.UTF_8));

            IdentityAuthority.initialize();
            IdentityAuthority.issueCertificate("Ana");
            IdentityAuthority.issueCertificate("Dan");
            var authorityPublicKey = IdentityAuthority.loadAuthorityPublicKey();
            DHState danIdentity = ChatClient.loadOrCreateNoiseIdentity("Dan");
            IdentityCertificate danCertificate = IdentityAuthority.loadCertificate("Dan");

            clientRun = executor.submit(() -> {
                new ChatClient("Ana", "127.0.0.1", fakeRelay.getLocalPort()).start();
                return null;
            });

            try (Socket peer = fakeRelay.accept()) {
                peer.setSoTimeout(5_000);
                BufferedReader peerInput = new BufferedReader(
                        new InputStreamReader(peer.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter peerOutput = new PrintWriter(peer.getOutputStream(), true, StandardCharsets.UTF_8);

                assertEquals("HELLO\tAna", peerInput.readLine());
                peerOutput.println("PEER\tDan");
                String[] firstHandshake = readPacket(peerInput, "HS");
                assertEquals("Ana", firstHandshake[1]);
                assertEquals("Dan", firstHandshake[2]);

                HandshakeState responder = new HandshakeState(NOISE_PROTOCOL, HandshakeState.RESPONDER);
                responder.getLocalKeyPair().copyFrom(danIdentity);
                responder.start();
                byte[] payload = new byte[Noise.MAX_PACKET_LEN];
                byte[] firstMessage = Base64.getDecoder().decode(firstHandshake[3]);
                assertEquals(0, responder.readMessage(firstMessage, 0, firstMessage.length, payload, 0));

                byte[] handshakeOutput = new byte[Noise.MAX_PACKET_LEN];
                byte[] certificatePayload = danCertificate.encode();
                int secondLength = responder.writeMessage(
                        handshakeOutput, 0, certificatePayload, 0, certificatePayload.length);
                peerOutput.println("HS\tDan\tAna\t" + Base64.getEncoder().encodeToString(
                        Arrays.copyOf(handshakeOutput, secondLength)));

                String[] finalHandshake = readPacket(peerInput, "HS");
                byte[] finalMessage = Base64.getDecoder().decode(finalHandshake[3]);
                int finalPayloadLength = responder.readMessage(
                        finalMessage, 0, finalMessage.length, payload, 0);
                IdentityCertificate anaCertificate = IdentityCertificate.decode(
                        Arrays.copyOf(payload, finalPayloadLength));
                assertTrue(anaCertificate.verify(authorityPublicKey));
                assertTrue(anaCertificate.matches("Ana", readPublicKey("Ana")));
                assertEquals(HandshakeState.SPLIT, responder.getAction());
                CipherStatePair transport = responder.split();
                responder.destroy();

                assertTrue(awaitOutput(consoleOutput, "[IDENTITATE OK] Certificat CA valid pentru Dan"));
                consoleWriter.write("salut\n".getBytes(StandardCharsets.UTF_8));
                consoleWriter.flush();

                String[] encryptedMessage = readPacket(peerInput, "MSG");
                assertEquals("Ana", encryptedMessage[1]);
                assertEquals("Dan", encryptedMessage[2]);
                byte[] ciphertext = Base64.getDecoder().decode(encryptedMessage[3]);
                byte[] plaintext = new byte[ciphertext.length];
                byte[] associatedData = "CHAT_e2ee_MSG_v1\tAna\tDan".getBytes(StandardCharsets.UTF_8);
                int plaintextLength = transport.getReceiver().decryptWithAd(
                        associatedData, ciphertext, 0, plaintext, 0, ciphertext.length);
                assertEquals("Ana: salut", new String(plaintext, 0, plaintextLength, StandardCharsets.UTF_8));

                byte[] reply = "Dan: salut".getBytes(StandardCharsets.UTF_8);
                byte[] replyCiphertext = new byte[reply.length + transport.getSender().getMACLength()];
                byte[] replyAd = "CHAT_e2ee_MSG_v1\tDan\tAna".getBytes(StandardCharsets.UTF_8);
                int replyLength = transport.getSender().encryptWithAd(
                        replyAd, reply, 0, replyCiphertext, 0, reply.length);
                peerOutput.println("MSG\tDan\tAna\t" + Base64.getEncoder().encodeToString(
                        Arrays.copyOf(replyCiphertext, replyLength)));
                assertTrue(awaitOutput(consoleOutput, "Dan: salut"));

                consoleWriter.write("/quit\n".getBytes(StandardCharsets.UTF_8));
                consoleWriter.flush();
                clientRun.get(5, TimeUnit.SECONDS);
                transport.destroy();
            }
        } finally {
            consoleWriter.close();
            if (clientRun != null && !clientRun.isDone()) clientRun.cancel(true);
            executor.shutdownNow();
            System.setIn(originalInput);
            System.setOut(originalOutput);
            if (originalHome == null) System.clearProperty("user.home");
            else System.setProperty("user.home", originalHome);
        }
    }

    private static byte[] readPublicKey(String name) throws Exception {
        byte[] key = new byte[32];
        DHState identity = ChatClient.loadOrCreateNoiseIdentity(name);
        try {
            identity.getPublicKey(key, 0);
        } finally {
            identity.destroy();
        }
        return key;
    }

    private static String[] readPacket(BufferedReader input, String type) throws Exception {
        String line = input.readLine();
        assertTrue(line != null && line.startsWith(type + "\t"), "Expected " + type + " packet, got: " + line);
        String[] fields = line.split("\t", -1);
        assertEquals(4, fields.length);
        return fields;
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
}
