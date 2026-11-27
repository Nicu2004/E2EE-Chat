package org.example;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

public class IdentityTest {

    @Test
    public void savedIdentityLoadsBackTheSameKey(@TempDir Path dir) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Identity id1 = Identity.loadOrStoreIdentity("Ana", dir);
        Identity id2 = Identity.loadOrStoreIdentity("Ana", dir);
        assertArrayEquals(id1.keyPair().getPublic().getEncoded(), id2.keyPair().getPublic().getEncoded());
    }
    @Test
    void invalidNameIsRejected(@TempDir Path dir) {
        assertThrows(IllegalArgumentException.class, () -> Identity.loadOrStoreIdentity("../x", dir));
    }
    @Test
    public void verifySignature(@TempDir Path dir) throws Exception {
        Identity identity = Identity.loadOrStoreIdentity("Ana", dir);
        byte[] message = "identity test".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(identity.keyPair().getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(identity.keyPair().getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(signature));
    }
    @Test
    public void testCorruptedFile(@TempDir Path dir) throws Exception {
        Identity.loadOrStoreIdentity("Ana", dir);
        Path identityFile = dir.resolve("Ana").resolve("identity.properties");
        Files.writeString(identityFile, "publicKey=not-base64!!!\nprivateKey=not-base64!!!\n");

        assertThrows(IllegalArgumentException.class, () -> Identity.loadOrStoreIdentity("Ana", dir));
    }
}
