# Chat criptat end-to-end (MVP)

Implementare Java 17 pentru cerinta de nota 7. Clientii folosesc X25519 pentru a stabili un secret comun si AES-GCM pentru criptare cu verificarea integritatii. Serverul doar tine conexiunile si retransmite pachete; nu are chei private si nu decripteaza mesajele.

## Pornire in IntelliJ IDEA

Foloseste JDK 17 sau mai nou. Deschide terminalul in `CHAT_e2ee/CHAT_e2ee` (folderul care contine `pom.xml`) si compileaza cu:

```text
javac --release 17 -d target/classes src/main/java/org/example/App.java src/main/java/org/example/RelayServer.java src/main/java/org/example/ChatClient.java
```

Deschide trei terminale in acelasi folder. In primul porneste serverul:

```text
java -cp target/classes org.example.App server
```

```text
java -cp target/classes org.example.App client Ana
```

```text
java -cp target/classes org.example.App client Dan
```

Scrie un mesaj in clientul Ana; Dan il va putea citi. Logul serverului va arata doar ca a retransmis un pachet criptat si dimensiunea lui. Opreste fiecare proces cu `Ctrl+C` sau inchide clientul scriind `/quit`.

## Cum functioneaza

1. Fiecare client genereaza o pereche privata/publica X25519 locala si trimite doar cheia publica serverului.
2. Serverul transmite cheile publice catre ceilalti clienti.
3. Fiecare pereche de clienti calculeaza independent acelasi secret X25519. Din acesta se deriva chei AES-GCM diferite pentru fiecare directie a conversatiei.
4. Clientul cripteaza textul inainte sa-l trimita. AES-GCM autentifica si continutul, asa ca un mesaj modificat nu se decripteaza cu succes.

Protocolul este in text simplu doar ca framing: comenzile HELLO/PEER/MSG, identificatorul destinatarului, nonce-ul si ciphertext-ul. Textul conversatiei este criptat. Pentru demonstratie, aratati textul clar in clientul destinatar simultan cu logurile releului.

## Limita de securitate

Schimbul cheilor publice nu verifica identitatea participantului. Un server ostil poate inlocui cheile publice si incerca un atac man-in-the-middle. Aceasta versiune este un MVP didactic, nu un produs sigur pentru mesaje reale. Verificarea amprentelor cheilor, rotirea cheilor si forward secrecy sunt extensii ulterioare.
