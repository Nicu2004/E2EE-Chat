package org.example;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
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
    public void verifySignature()
    {

    }
    @Test
    public void testCorruptedFile()
    {

    }
}
