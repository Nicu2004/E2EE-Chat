package org.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;

final class IdentityAuthority {
    private static final String AUTHORITY_PRIVATE_FILE = "authority_private.key";
    private static final String AUTHORITY_PUBLIC_FILE = "authority_public.key";

    private IdentityAuthority() {}

    static void initialize() throws Exception {
        Path directory = storageDirectory();
        Files.createDirectories(directory);
        Path privateFile = directory.resolve(AUTHORITY_PRIVATE_FILE);
        Path publicFile = directory.resolve(AUTHORITY_PUBLIC_FILE);
        if (Files.exists(privateFile) || Files.exists(publicFile)) {
            throw new IOException("Autoritatea exista deja; cheile existente nu au fost suprascrise.");
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair authority = generator.generateKeyPair();
        Files.write(privateFile, authority.getPrivate().getEncoded());
        Files.write(publicFile, authority.getPublic().getEncoded());
        setPrivatePermissions(privateFile);
        System.out.println("Autoritatea Ed25519 a fost creata.");
        System.out.println("Cheia privata (secreta): " + privateFile);
        System.out.println("Cheia publica (distribuiti-o clientilor printr-un canal sigur): " + publicFile);
    }

    static void issueCertificate(String profileName) throws Exception {
        validateName(profileName);
        Path directory = storageDirectory();
        Path privateFile = directory.resolve(AUTHORITY_PRIVATE_FILE);
        if (!Files.exists(privateFile)) {
            throw new IOException("Lipseste autoritatea. Rulati mai intai: authority-init");
        }

        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateFile)));
        byte[] publicKey = new byte[32];
        var identity = ChatClient.loadOrCreateNoiseIdentity(profileName);
        try {
            identity.getPublicKey(publicKey, 0);
        } finally {
            identity.destroy();
        }

        IdentityCertificate certificate = IdentityCertificate.issue(profileName, publicKey, privateKey);
        Path certificateFile = directory.resolve(profileName + "_noise_identity.cert");
        Files.write(certificateFile, certificate.encode());
        System.out.println("Certificat emis pentru " + profileName + ": " + certificateFile);
    }

    static PublicKey loadAuthorityPublicKey() throws Exception {
        Path publicFile = storageDirectory().resolve(AUTHORITY_PUBLIC_FILE);
        if (!Files.exists(publicFile)) {
            throw new IOException("Lipseste authority_public.key din " + storageDirectory()
                    + ". Copiati cheia publica a autoritatii printr-un canal sigur.");
        }
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicFile)));
    }

    static IdentityCertificate loadCertificate(String profileName) throws Exception {
        Path certificateFile = storageDirectory().resolve(profileName + "_noise_identity.cert");
        if (!Files.exists(certificateFile)) {
            throw new IOException("Lipseste certificatul " + certificateFile
                    + ". Rulati authority-issue " + profileName + " pe calculatorul autoritatii.");
        }
        return IdentityCertificate.decode(Files.readAllBytes(certificateFile));
    }

    private static Path storageDirectory() {
        return Paths.get(System.getProperty("user.home"), ".chat_tofu");
    }

    private static void validateName(String name) {
        if (name == null || !name.matches("[A-Za-z0-9_]{1,32}")) {
            throw new IllegalArgumentException("Numele poate contine doar litere, cifre si underscore.");
        }
    }

    private static void setPrivatePermissions(Path path) {
        try {
            Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException | IOException ignored) {
        }
    }
}
