package org.example;

public final class App {
    private App() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "help".equalsIgnoreCase(args[0])) {
            System.out.println("Comenzi:");
            System.out.println("  java -cp target/classes org.example.App server [port]");
            System.out.println("  java -cp target/classes org.example.App client <nume> [host] [port]");
            return;
        }
        switch (args[0].toLowerCase()) {
            case "server" -> {
                int port = args.length > 1 ? Integer.parseInt(args[1]) : 8765;
                new RelayServer(port).start();
            }
            case "client" -> {
                if (args.length < 2) throw new IllegalArgumentException("Lipseste numele: client <nume> [host] [port]");
                String host = args.length > 2 ? args[2] : "127.0.0.1";
                int port = args.length > 3 ? Integer.parseInt(args[3]) : 8765;
                new ChatClient(args[1], host, port).start();
            }
            default -> throw new IllegalArgumentException("Rol necunoscut: " + args[0] + ". Foloseste server sau client.");
        }
    }
}
