package org.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class RelayServerTest {

    @Test
    void registersPeersRelaysMessagesAndNotifiesOnDisconnect() throws Exception {
        try (RelayServerTestSupport.RunningRelay relay = RelayServerTestSupport.start();
             Socket alice = connect(relay.port());
             Socket bob = connect(relay.port())) {
            alice.setSoTimeout(3_000);
            bob.setSoTimeout(3_000);

            BufferedReader aliceIn = reader(alice);
            PrintWriter aliceOut = writer(alice);
            BufferedReader bobIn = reader(bob);
            PrintWriter bobOut = writer(bob);
            KeyPair aliceKeys = generateKeys();
            KeyPair bobKeys = generateKeys();

            sendHello(aliceOut, "alice", aliceKeys);
            sendHello(bobOut, "bob", bobKeys);

            assertEquals("PEER\tbob\t" + publicKey(bobKeys), aliceIn.readLine());
            assertEquals("PEER\talice\t" + publicKey(aliceKeys), bobIn.readLine());

            String nonce = Base64.getEncoder().encodeToString(new byte[12]);
            String ciphertext = Base64.getEncoder().encodeToString(new byte[16]);
            aliceOut.println("MSG\tuntrusted-sender\tbob\t" + nonce + "\t" + ciphertext);

            assertEquals("MSG\talice\t" + nonce + "\t" + ciphertext, readNextNonPeerPacket(bobIn));
            alice.shutdownOutput();
            assertEquals("LEFT\talice", bobIn.readLine());
        }
    }

    @Test
    void closesConnectionWhenHelloPacketIsInvalid() throws Exception {
        try (RelayServerTestSupport.RunningRelay relay = RelayServerTestSupport.start();
             Socket client = connect(relay.port())) {
            client.setSoTimeout(3_000);
            writer(client).println("INVALID");
            assertNull(reader(client).readLine());
        }
    }

    private static Socket connect(int port) throws Exception {
        return new Socket("127.0.0.1", port);
    }

    private static BufferedReader reader(Socket socket) throws Exception {
        return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
    }

    private static PrintWriter writer(Socket socket) throws Exception {
        return new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
    }

    private static KeyPair generateKeys() throws Exception {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    private static String publicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    private static void sendHello(PrintWriter out, String id, KeyPair keyPair) {
        out.println("HELLO\t" + id + "\t" + publicKey(keyPair));
    }

    private static String readNextNonPeerPacket(BufferedReader in) throws Exception {
        String packet;
        do {
            packet = in.readLine();
        } while (packet != null && packet.startsWith("PEER\t"));
        return packet;
    }
}
