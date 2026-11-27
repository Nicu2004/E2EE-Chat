package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Queue;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.southernstorm.noise.protocol.CipherStatePair;
import com.southernstorm.noise.protocol.DHState;
import com.southernstorm.noise.protocol.Noise;
import com.southernstorm.noise.protocol.HandshakeState;

public final class ChatClient {
    private static final String NOISE_PROTOCOL = "Noise_XX_25519_AESGCM_SHA256";
    private static final int REKEY_AFTER_MESSAGES = 100;
    private static final int MAX_CIPHERTEXT_LENGTH = 65_535;
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final String name;
    private final String host;
    private final int port;
    private final String id;
    private final Map<String, PeerSession> sessions = new ConcurrentHashMap<>();
    private final Object writeLock = new Object();
    private PrintWriter out;
    private DHState noiseIdentity;
    private PublicKey authorityPublicKey;
    private byte[] identityCertificatePayload;

    public ChatClient(String name, String host, int port) {
        this.name = name;
        this.host = host;
        this.port = port;
        this.id = name;
    }

    public void start() throws Exception {
        noiseIdentity = loadOrCreateNoiseIdentity(name);
        authorityPublicKey = IdentityAuthority.loadAuthorityPublicKey();
        IdentityCertificate localCertificate = IdentityAuthority.loadCertificate(name);
        byte[] localStaticPublicKey = new byte[noiseIdentity.getPublicKeyLength()];
        noiseIdentity.getPublicKey(localStaticPublicKey, 0);
        if (!localCertificate.verify(authorityPublicKey)
                || !localCertificate.matches(name, localStaticPublicKey)) {
            throw new IOException("Certificatul local nu este valid sau nu corespunde identitatii Noise " + name + ".");
        }
        identityCertificatePayload = localCertificate.encode();
        BufferedReader console = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        Thread receiver;

        try (Socket socket = new Socket(host, port)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
            send("HELLO\t" + id);
            System.out.println("Conectat ca " + name + " (" + id + "). Asteapta alt participant; /quit inchide chatul.");

            receiver = new Thread(() -> receive(in), "chat-receiver");
            receiver.setDaemon(true);
            receiver.start();

            String text;
            while ((text = console.readLine()) != null && !"/quit".equalsIgnoreCase(text)) {
                boolean sent = false;
                for (Map.Entry<String, PeerSession> entry : sessions.entrySet()) {
                    if (sendChatMessage(entry.getKey(), entry.getValue(), text)) {
                        sent = true;
                    }
                }
                if (!sent) {
                    System.out.println("Nu exista un interlocutor cu certificat valid al autoritatii.");
                }
            }
        }

        receiver.join();
        System.out.println("Client inchis.");
    }

    private void receive(BufferedReader in) {
        try {
            String line;
            while ((line = in.readLine()) != null) {
                String[] fields = line.split("\\t", -1);
                if (fields.length == 2 && "PEER".equals(fields[0])) {
                    handlePeer(fields[1]);
                } else if (fields.length == 4 && "HS".equals(fields[0])) {
                    handleHandshake(fields);
                } else if (fields.length == 4 && "MSG".equals(fields[0])) {
                    handleMessage(fields);
                } else if (fields.length == 2 && "LEFT".equals(fields[0])) {
                    destroySession(sessions.remove(fields[1]));
                    System.out.println("[INFO] Participantul " + fields[1] + " s-a deconectat.");
                }
            }
        } catch (IOException e) {
            System.out.println("Conexiunea cu serverul s-a inchis.");
        }
    }

    private void handleHandshake(String[] fields) {
        String peerId = fields[1];
        if (!id.equals(fields[2])) {
            System.out.println("[EROARE] Pachetul Noise este destinat altui client.");
            return;
        }

        PeerSession session = sessions.get(peerId);
        if (session == null) {
            System.out.println("[EROARE NOISE] Nu exista sesiune cu " + peerId + ".");
            return;
        }

        try {
            byte[] message = B64D.decode(fields[3]);
            synchronized (session) {
                if (session.handshake == null) {
                    if (session.transport == null) {
                        throw new IOException("Sesiunea nu are handshake activ sau transport stabilit.");
                    }
                    session.handshake = createHandshake(HandshakeState.RESPONDER);
                    session.remoteCertificate = null;
                }

                byte[] payload = new byte[Noise.MAX_PACKET_LEN];
                int payloadLength = session.handshake.readMessage(message, 0, message.length, payload, 0);
                if (payloadLength > 0) {
                    session.remoteCertificate = IdentityCertificate.decode(Arrays.copyOf(payload, payloadLength));
                }

                if (session.handshake.getAction() == HandshakeState.WRITE_MESSAGE) {
                    byte[] output = new byte[Noise.MAX_PACKET_LEN];
                    int messageLength = session.handshake.writeMessage(
                            output, 0, identityCertificatePayload, 0, identityCertificatePayload.length);
                    byte[] response = Arrays.copyOf(output, messageLength);
                    send("HS\t" + id + "\t" + peerId + "\t" + B64.encodeToString(response));
                }

                if (session.handshake.getAction() == HandshakeState.SPLIT) {
                    finishHandshake(peerId, session);
                }
            }
        } catch (Exception e) {
            sessions.remove(peerId, session);
            destroySession(session);
            System.out.println("[EROARE NOISE] Handshake-ul cu " + peerId + " a esuat: " + e.getMessage());
        }
    }

    private void finishHandshake(String peerId, PeerSession session) throws Exception {
        DHState remoteStaticKey = session.handshake.getRemotePublicKey();
        byte[] remotePublicKey = new byte[remoteStaticKey.getPublicKeyLength()];
        remoteStaticKey.getPublicKey(remotePublicKey, 0);
        IdentityCertificate remoteCertificate = session.remoteCertificate;
        if (remoteCertificate == null || !remoteCertificate.verify(authorityPublicKey)
                || !remoteCertificate.matches(peerId, remotePublicKey)) {
            throw new IOException("Certificatul interlocutorului lipseste, are semnatura invalida sau alta cheie.");
        }
        CipherStatePair previousTransport = session.transport;
        HandshakeState completedHandshake = session.handshake;
        session.transport = completedHandshake.split();
        session.handshake = null;
        completedHandshake.destroy();
        session.messagesSinceRekey = 0;
        if (previousTransport != null) {
            previousTransport.destroy();
            System.out.println("[NOISE] Cheile de transport au fost rotite pentru " + peerId + ".");
        }

        session.trusted = true;
        session.remoteCertificate = null;
        System.out.println("[IDENTITATE OK] Certificat CA valid pentru " + peerId + ".");
        flushQueuedMessages(peerId, session);
    }

    private void destroySession(PeerSession session) {
        if (session == null) {
            return;
        }
        if (session.transport != null) {
            session.transport.destroy();
        }
        if (session.handshake != null) {
            session.handshake.destroy();
        }
    }

    private void handlePeer(String peerId) {
        if (id.equals(peerId) || sessions.containsKey(peerId)) {
            return;
        }

        int role = id.compareTo(peerId) < 0 ? HandshakeState.INITIATOR : HandshakeState.RESPONDER;
        HandshakeState handshake = null;
        PeerSession session = null;
        try {
            handshake = createHandshake(role);

            session = new PeerSession(handshake);
            PeerSession existing = sessions.putIfAbsent(peerId, session);
            if (existing != null) {
                handshake.destroy();
                return;
            }

            if (role == HandshakeState.INITIATOR) {
                byte[] output = new byte[Noise.MAX_PACKET_LEN];
                int messageLength = handshake.writeMessage(output, 0, new byte[0], 0, 0);
                byte[] message = Arrays.copyOf(output, messageLength);
                send("HS\t" + id + "\t" + peerId + "\t" + B64.encodeToString(message));
                System.out.println("[NOISE] Handshake initiat cu " + peerId + ".");
            } else {
                System.out.println("[NOISE] Astept primul pachet de handshake de la " + peerId + ".");
            }
        } catch (Exception e) {
            if (session != null) {
                sessions.remove(peerId, session);
            }
            if (handshake != null) {
                handshake.destroy();
            }
            System.out.println("[EROARE NOISE] Nu s-a putut porni sesiunea cu " + peerId + ": " + e.getMessage());
        }
    }

    private HandshakeState createHandshake(int role) throws Exception {
        HandshakeState handshake = new HandshakeState(NOISE_PROTOCOL, role);
        handshake.getLocalKeyPair().copyFrom(noiseIdentity);
        handshake.start();
        return handshake;
    }

    private boolean sendChatMessage(String peerId, PeerSession session, String text) {
        synchronized (session) {
            if (!session.trusted || session.transport == null) {
                return false;
            }
            byte[] plaintext = (name + ": " + text).getBytes(StandardCharsets.UTF_8);
            if (session.handshake != null) {
                session.pendingMessages.add(plaintext);
                System.out.println("[NOISE] Mesaj pus in coada pana se termina rotirea cheilor cu " + peerId + ".");
                return true;
            }
            try {
                sendEncrypted(peerId, session, plaintext);
                return true;
            } catch (Exception e) {
                String detail = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                System.out.println("[EROARE] Nu s-a putut cripta mesajul pentru " + peerId + ": " + detail);
                return false;
            }
        }
    }

    private void sendEncrypted(String peerId, PeerSession session, byte[] plaintext) throws Exception {
        byte[] ad = messageAd(id, peerId);
        int macLength = session.transport.getSender().getMACLength();
        if (plaintext.length + macLength > MAX_CIPHERTEXT_LENGTH) {
            throw new IOException("Mesajul este prea mare pentru un singur pachet.");
        }
        byte[] ciphertext = new byte[plaintext.length + macLength];
        int ciphertextLength = session.transport.getSender().encryptWithAd(
                ad, plaintext, 0, ciphertext, 0, plaintext.length);
        send("MSG\t" + id + "\t" + peerId + "\t"
                + B64.encodeToString(Arrays.copyOf(ciphertext, ciphertextLength)));
        session.messagesSinceRekey++;

        if (session.messagesSinceRekey >= REKEY_AFTER_MESSAGES && id.compareTo(peerId) < 0) {
            beginRekey(peerId, session);
        }
    }

    private void beginRekey(String peerId, PeerSession session) throws Exception {
        session.remoteCertificate = null;
        session.handshake = createHandshake(HandshakeState.INITIATOR);
        byte[] output = new byte[Noise.MAX_PACKET_LEN];
        int messageLength = session.handshake.writeMessage(output, 0, new byte[0], 0, 0);
        send("HS\t" + id + "\t" + peerId + "\t"
                + B64.encodeToString(Arrays.copyOf(output, messageLength)));
        System.out.println("[NOISE] Rotirea cheilor a inceput cu " + peerId + ".");
    }

    private void flushQueuedMessages(String peerId, PeerSession session) throws Exception {
        while (session.trusted && session.handshake == null && !session.pendingMessages.isEmpty()) {
            sendEncrypted(peerId, session, session.pendingMessages.remove());
        }
    }

    private void handleMessage(String[] fields) {
        String peerId = fields[1];
        if (!id.equals(fields[2])) {
            System.out.println("[EROARE] Mesajul este destinat altui client.");
            return;
        }
        PeerSession session = sessions.get(peerId);
        if (session == null) {
            System.out.println("[EROARE] Mesaj primit fara sesiune Noise de la " + peerId + ".");
            return;
        }
        try {
            byte[] ciphertext = B64D.decode(fields[3]);
            if (ciphertext.length < 16 || ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
                throw new IOException("Dimensiune invalida pentru pachetul criptat.");
            }
            synchronized (session) {
                if (!session.trusted || session.transport == null || session.handshake != null) {
                    throw new IOException("Sesiunea nu este verificata sau este in curs de rotire.");
                }
                byte[] plaintext = new byte[ciphertext.length];
                int plaintextLength = session.transport.getReceiver().decryptWithAd(
                        messageAd(peerId, id), ciphertext, 0, plaintext, 0, ciphertext.length);
                System.out.println(new String(plaintext, 0, plaintextLength, StandardCharsets.UTF_8));
                session.messagesSinceRekey++;
                if (session.messagesSinceRekey >= REKEY_AFTER_MESSAGES && id.compareTo(peerId) < 0) {
                    beginRekey(peerId, session);
                }
            }
        } catch (Exception e) {
            System.out.println("[EROARE] Mesaj invalid, alterat sau primit in timpul rotirii cheilor de la "
                    + peerId + ".");
        }
    }

    private static byte[] messageAd(String from, String to) {
        return ("CHAT_e2ee_MSG_v1\t" + from + "\t" + to).getBytes(StandardCharsets.UTF_8);
    }

    private void send(String line) {
        synchronized (writeLock) {
            out.println(line);
        }
    }

    static DHState loadOrCreateNoiseIdentity(String profileName) throws Exception {
        if (profileName == null || !profileName.matches("[A-Za-z0-9_]{1,32}")) {
            throw new IllegalArgumentException("Numele profilului poate contine doar litere, cifre si underscore.");
        }

        Path directory = Paths.get(System.getProperty("user.home"), ".chat_tofu");
        Files.createDirectories(directory);
        Path privateFile = directory.resolve(profileName + "_noise_private.key");
        Path publicFile = directory.resolve(profileName + "_noise_public.key");

        boolean privateExists = Files.exists(privateFile);
        boolean publicExists = Files.exists(publicFile);
        DHState identity = Noise.createDH("25519");

        if (privateExists != publicExists) {
            throw new IOException("Perechea de chei Noise pentru " + profileName
                    + " este incompleta; lipseste cheia privata sau publica.");
        }

        if (privateExists) {
            byte[] privateKey = Files.readAllBytes(privateFile);
            byte[] publicKey = Files.readAllBytes(publicFile);
            if (privateKey.length != identity.getPrivateKeyLength()
                    || publicKey.length != identity.getPublicKeyLength()) {
                throw new IOException("Cheile Noise salvate pentru " + profileName + " au dimensiuni invalide.");
            }
            identity.setPublicKey(publicKey, 0);
            identity.setPrivateKey(privateKey, 0);
            return identity;
        }

        identity.generateKeyPair();
        byte[] privateKey = new byte[identity.getPrivateKeyLength()];
        byte[] publicKey = new byte[identity.getPublicKeyLength()];
        identity.getPrivateKey(privateKey, 0);
        identity.getPublicKey(publicKey, 0);

        Files.write(privateFile, privateKey);
        Files.write(publicFile, publicKey);
        try {
            Set<PosixFilePermission> privatePermissions = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(privateFile, privatePermissions);
        } catch (UnsupportedOperationException ignored) {
        }

        return identity;
    }

    private static final class PeerSession {
        private HandshakeState handshake;
        private CipherStatePair transport;
        private boolean trusted;
        private IdentityCertificate remoteCertificate;
        private int messagesSinceRekey;
        private final Queue<byte[]> pendingMessages = new ArrayDeque<>();

        private PeerSession(HandshakeState handshake) {
            this.handshake = handshake;
        }
    }
}
