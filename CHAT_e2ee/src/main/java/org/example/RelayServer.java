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
            String[] helloFields = fields(hello, 2);

            if (!"HELLO".equals(helloFields[0])) throw new IOException("Primul pachet trebuie sa fie HELLO");
            id = helloFields[1];
            if (!id.matches("[A-Za-z0-9_]{1,32}")) throw new IOException("ID invalid");

            Peer newcomer = new Peer(id, out);
            if (peers.putIfAbsent(id, newcomer) != null) throw new IOException("ID duplicat");
            registered = true;

            System.out.println("[RELEU] conectat " + id);
            for (Peer peer : peers.values()) {
                if (!peer.id.equals(id)) {
                    newcomer.send("PEER\t" + peer.id);
                    peer.send("PEER\t" + id);
                }
            }

            String line;
            while ((line = in.readLine()) != null) {
                String[] header = line.split("\\t", -1);
                if (header.length == 0) throw new IOException("Pachet invalid");

                if ("HS".equals(header[0])) {
                    String[] packet = fields(line, 4);
                    if (!id.equals(packet[1])) throw new IOException("Expeditor HS nevalid");
                    if (id.equals(packet[2])) continue;

                    byte[] handshakeMessage = Base64.getDecoder().decode(packet[3]);
                    if (handshakeMessage.length == 0 || handshakeMessage.length > 65_535) continue;
                    Peer recipient = peers.get(packet[2]);
                    if (recipient != null) {
                        recipient.send(line);
                        System.out.println("[RELEU] pachet HS retransmis; " + handshakeMessage.length + " octeti");
                    }
                } else if ("MSG".equals(header[0])) {
                    String[] packet = fields(line, 4);
                    if (!id.equals(packet[1])) throw new IOException("Expeditor MSG nevalid");
                    if (id.equals(packet[2])) continue;

                    byte[] ciphertext = Base64.getDecoder().decode(packet[3]);
                    if (ciphertext.length < 16 || ciphertext.length > 65_535) continue;
                    Peer recipient = peers.get(packet[2]);
                    if (recipient != null) {
                        recipient.send(line);
                        System.out.println("[RELEU] pachet criptat retransmis; " + ciphertext.length + " octeti");
                    }
                } else {
                    throw new IOException("Tip de pachet necunoscut");
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
        private final PrintWriter out;
        private Peer(String id, PrintWriter out) {
            this.id = id;
            this.out = out;
        }
        private synchronized void send(String line) { out.println(line); }
    }
}
