package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Clientul genereaza cheile si cripteaza/decripteaza mesajele. */
public final class ChatClient {
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final String name;
    private final String host;
    private final int port;
    private final String id = UUID.randomUUID().toString();
    private final Map<String, PeerKeys> peerKeys = new ConcurrentHashMap<>();
    private final AtomicLong nonceCounter = new AtomicLong();
    private final Object writeLock = new Object();
    private KeyPair keyPair;
    private PrintWriter out;

    public ChatClient(String name, String host, int port) { this.name = name; this.host = host; this.port = port; }

    public void start() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
        keyPair = generator.generateKeyPair();
        try (Socket socket = new Socket(host, port);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedReader console = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
            send("HELLO\t" + id + "\t" + B64.encodeToString(keyPair.getPublic().getEncoded()));
            System.out.println("Conectat ca " + name + " (" + id + "). Asteapta alt participant; /quit inchide chatul.");

            Thread receiver = new Thread(() -> receive(in), "chat-receiver");
            receiver.setDaemon(true);
            receiver.start();

            String text;
            while ((text = console.readLine()) != null && !"/quit".equalsIgnoreCase(text)) {
                if (peerKeys.isEmpty()) {
                    System.out.println("Nu exista inca alt participant conectat; mesajul nu a fost trimis.");
                    continue;
                }
                for (Map.Entry<String, PeerKeys> peer : peerKeys.entrySet()) {
                    byte[] nonce = nextNonce();
                    byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, peer.getValue().sendKey, nonce, (name + ": " + text).getBytes(StandardCharsets.UTF_8));
                    send("MSG\t" + id + "\t" + peer.getKey() + "\t" + B64.encodeToString(nonce) + "\t" + B64.encodeToString(ciphertext));
                }
            }
        }
        System.out.println("Client inchis.");
    }

    private void receive(BufferedReader in) {
        try {
            String line;
            while ((line = in.readLine()) != null) {
                String[] p = line.split("\\t", -1);
                if (p.length == 3 && "PEER".equals(p[0])) {
                    try {
                        PublicKey publicKey = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(B64D.decode(p[2])));
                        peerKeys.put(p[1], deriveKeys(publicKey, p[1]));
                        System.out.println("[INFO] Participant " + p[1] + " conectat; cheia comuna calculata.");
                    } catch (Exception e) {
                        System.out.println("[EROARE] Cheia publica primita nu este valida.");
                    }
                } else if (p.length == 4 && "MSG".equals(p[0])) {
                    PeerKeys keys = peerKeys.get(p[1]);
                    if (keys == null) continue;
                    try {
                        byte[] clear = crypt(Cipher.DECRYPT_MODE, keys.receiveKey, B64D.decode(p[2]), B64D.decode(p[3]));
                        System.out.println(new String(clear, StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        System.out.println("[EROARE] Mesaj alterat sau trimis de cineva fara cheia corecta.");
                    }
                } else if (p.length == 2 && "LEFT".equals(p[0])) {
                    peerKeys.remove(p[1]);
                    System.out.println("[INFO] Participantul " + p[1] + " s-a deconectat.");
                }
            }
        } catch (IOException e) {
            System.out.println("Conexiunea cu serverul s-a inchis.");
        }
    }

    private PeerKeys deriveKeys(PublicKey peerPublicKey, String peerId) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(keyPair.getPrivate());
        agreement.doPhase(peerPublicKey, true);
        byte[] shared = agreement.generateSecret();
        // HKDF-SHA256: chei AES-GCM diferite pentru fiecare sens al conversatiei.
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] salt = "CHAT_e2ee_demo_v1".getBytes(StandardCharsets.UTF_8);
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(shared);
        byte[] sendKey = expand(mac, prk, "chat message key:" + id);
        byte[] receiveKey = expand(mac, prk, "chat message key:" + peerId);
        return new PeerKeys(sendKey, receiveKey);
    }

    private static byte[] expand(Mac mac, byte[] prk, String label) throws Exception {
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update((label + "\u0001").getBytes(StandardCharsets.UTF_8));
        return mac.doFinal();
    }

    private byte[] nextNonce() throws Exception {
        // Contorul produce nonce-uri unice in cadrul cheii de trimitere; cheia este unica pentru aceasta sesiune/sens.
        byte[] nonce = new byte[12];
        long value = nonceCounter.getAndIncrement();
        for (int i = 0; i < 8; i++) nonce[4 + i] = (byte) (value >>> (56 - i * 8));
        return nonce;
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(input);
    }

    private void send(String line) {
        synchronized (writeLock) { out.println(line); }
    }

    private static final class PeerKeys {
        private final byte[] sendKey;
        private final byte[] receiveKey;
        private PeerKeys(byte[] sendKey, byte[] receiveKey) { this.sendKey = sendKey; this.receiveKey = receiveKey; }
    }
}
