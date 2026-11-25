package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Serverul nu decripteaza: tine conexiunile si retransmite linii de protocol. */
public final class RelayServer implements AutoCloseable {
    private final int port;
    private final Map<String, Peer> peers = new ConcurrentHashMap<>();
    private volatile ServerSocket serverSocket;

    public RelayServer(int port) { this.port = port; }

    public void start() throws IOException {
        try (ServerSocket server = new ServerSocket(port)) {
            serverSocket = server;
            System.out.println("Releu pornit pe portul " + port + ". Oprire: Ctrl+C");
            try {
                while (true) {
                    Socket socket = server.accept();
                    Thread thread = new Thread(() -> handle(socket), "peer-handler");
                    thread.setDaemon(true);
                    thread.start();
                }
            } catch (SocketException e) {
                if (!server.isClosed()) throw e;
            } finally {
                serverSocket = null;
            }
        }
    }

    @Override
    public void close() throws IOException {
        ServerSocket server = serverSocket;
        if (server != null) server.close();
    }

    private void handle(Socket socket) {
        String id = null;
        boolean registered = false;
        try (socket;
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
            String hello = in.readLine();
            String[] helloFields = fields(hello, 3);

            if (!"HELLO".equals(helloFields[0])) throw new IOException("Primul pachet trebuie sa fie HELLO");
            id = helloFields[1];
            String publicKey = helloFields[2];
            Base64.getDecoder().decode(publicKey);
            Peer newcomer = new Peer(id, publicKey, out);
            if (peers.putIfAbsent(id, newcomer) != null) throw new IOException("ID duplicat");
            registered = true;

            System.out.println("[RELEU] conectat " + id + "; cheie publica primita");
            for (Peer peer : peers.values()) {
                if (!peer.id.equals(id)) {
                    newcomer.send("PEER\t" + peer.id + "\t" + peer.publicKey);
                    peer.send("PEER\t" + id + "\t" + publicKey);
                }
            }

            String line;
            while ((line = in.readLine()) != null) {
                String[] packet = fields(line, 5);
                if (!"MSG".equals(packet[0])) continue;
                byte[] nonce = Base64.getDecoder().decode(packet[3]);
                byte[] ciphertext = Base64.getDecoder().decode(packet[4]);
                if (nonce.length != 12 || ciphertext.length < 16) continue;
                System.out.println("[RELEU] pachet criptat retransmis; " + ciphertext.length + " octeti");
                Peer recipient = peers.get(packet[2]);
                if (recipient != null && !recipient.id.equals(id)) {
                    recipient.send("MSG\t" + id + "\t" + packet[3] + "\t" + packet[4]);
                }
            }
        } catch (IOException | IllegalArgumentException e) {
            System.out.println("[RELEU] conexiune inchisa: " + e.getMessage());
        } finally {
            if (registered && id != null && peers.remove(id) != null) {
                for (Peer peer : peers.values()) peer.send("LEFT\t" + id);
                System.out.println("[RELEU] deconectat " + id);
            }
        }
    }

    private static String[] fields(String line, int count) throws IOException {
        if (line == null) throw new IOException("Conexiune inchisa in timpul handshake-ului");
        String[] result = line.split("\\t", -1);
        if (result.length != count) throw new IOException("Pachet invalid");
        return result;
    }

    private static final class Peer {
        private final String id;
        private final String publicKey;
        private final PrintWriter out;
        private Peer(String id, String publicKey, PrintWriter out) {
            this.id = id; this.publicKey = publicKey; this.out = out;
        }
        private synchronized void send(String line) { out.println(line); }
    }
}
