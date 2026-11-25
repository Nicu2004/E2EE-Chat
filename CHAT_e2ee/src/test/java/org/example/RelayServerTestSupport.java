package org.example;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

final class RelayServerTestSupport {
    private RelayServerTestSupport() {}

    static RunningRelay start() throws Exception {
        int port;
        try (ServerSocket reservation = new ServerSocket(0)) {
            port = reservation.getLocalPort();
        }

        RelayServer relay = new RelayServer(port);
        AtomicReference<IOException> failure = new AtomicReference<>();
        Thread thread = new Thread(() -> {
            try {
                relay.start();
            } catch (IOException e) {
                failure.set(e);
            }
        }, "relay-server-test");
        thread.setDaemon(true);
        thread.start();

        long deadline = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < deadline) {
            IOException startupFailure = failure.get();
            if (startupFailure != null) throw startupFailure;

            try (Socket probe = new Socket()) {
                probe.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return new RunningRelay(relay, thread, port);
            } catch (ConnectException e) {
                Thread.sleep(10);
            }
        }

        relay.close();
        throw new IOException("Relay server did not start in time");
    }

    static final class RunningRelay implements AutoCloseable {
        private final RelayServer relay;
        private final Thread thread;
        private final int port;

        private RunningRelay(RelayServer relay, Thread thread, int port) {
            this.relay = relay;
            this.thread = thread;
            this.port = port;
        }

        int port() {
            return port;
        }

        @Override
        public void close() throws IOException {
            relay.close();
            try {
                thread.join(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while stopping relay server", e);
            }
            if (thread.isAlive()) throw new AssertionError("Relay server did not stop");
        }
    }
}
