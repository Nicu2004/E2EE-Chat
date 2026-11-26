package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Properties;
import java.util.Set;

public final class FileTrustStore {
    private final Path storeDir;
    private final Path storeFile;
    private final Properties properties = new Properties();

 
    public FileTrustStore(String profileName) throws IOException {
        String userHome = System.getProperty("user.home");
        this.storeDir = Paths.get(userHome, ".chat_tofu");
        this.storeFile = storeDir.resolve("known_hosts_" + profileName + ".properties");
        initStorage();
    }

    private void initStorage() throws IOException {
    
        if (!Files.exists(storeDir)) {
            Files.createDirectories(storeDir);
            setPosixPermissions(storeDir, "rwx------");
        }

        if (!Files.exists(storeFile)) {
            saveAtomic();
        } else {
            try (InputStream in = Files.newInputStream(storeFile)) {
                properties.load(in);
            }
        }
    }

    
    public synchronized String getFingerprint(String peerId) {
        return properties.getProperty(peerId);
    }

  
    public synchronized void saveFingerprint(String peerId, String fingerprint) throws IOException {
        properties.setProperty(peerId, fingerprint);
        saveAtomic();
    }

    public synchronized void removeFingerprint(String peerId) throws IOException {
        if (properties.remove(peerId) != null) {
            saveAtomic();
        }
    }

    private void saveAtomic() throws IOException {
        Path tempFile = storeDir.resolve(storeFile.getFileName() + ".tmp");
        try (OutputStream out = Files.newOutputStream(tempFile)) {
            properties.store(out, "TOFU Known Peers - Nu modifica manual");
        }
        setPosixPermissions(tempFile, "rw-------"); 
        Files.move(tempFile, storeFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private void setPosixPermissions(Path path, String perms) {
        try {
            Set<PosixFilePermission> permissions = PosixFilePermissions.fromString(perms);
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException | IOException ignored) {
        }
    }
}
