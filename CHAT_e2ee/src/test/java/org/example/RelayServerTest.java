package org.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
            sendHello(aliceOut, "alice");
            sendHello(bobOut, "bob");

            assertEquals("PEER\tbob", aliceIn.readLine());
            assertEquals("PEER\talice", bobIn.readLine());

            String ciphertext = Base64.getEncoder().encodeToString(new byte[16]);
            aliceOut.println("MSG\talice\tbob\t" + ciphertext);

            assertEquals("MSG\talice\tbob\t" + ciphertext, readNextNonPeerPacket(bobIn));
            String handshake = Base64.getEncoder().encodeToString(new byte[] {1, 2, 3, 4});
            aliceOut.println("HS\talice\tbob\t" + handshake);
            assertEquals("HS\talice\tbob\t" + handshake, readNextNonPeerPacket(bobIn));
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

    private static void sendHello(PrintWriter out, String id) {
        out.println("HELLO\t" + id);
    }

    private static String readNextNonPeerPacket(BufferedReader in) throws Exception {
        String packet;
        do {
            packet = in.readLine();
        } while (packet != null && packet.startsWith("PEER\t"));
        return packet;
    }
}
