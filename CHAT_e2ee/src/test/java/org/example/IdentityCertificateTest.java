package org.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class IdentityCertificateTest {
    @Test
    void certificateBindsNameAndNoiseKeyToAuthority() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair authority = generator.generateKeyPair();
        byte[] noisePublicKey = new byte[32];
        Arrays.fill(noisePublicKey, (byte) 9);

        IdentityCertificate certificate = IdentityCertificate.issue("Ana", noisePublicKey, authority.getPrivate());
        IdentityCertificate decoded = IdentityCertificate.decode(certificate.encode());

        assertTrue(decoded.verify(authority.getPublic()));
        assertTrue(decoded.matches("Ana", noisePublicKey));
        assertFalse(decoded.matches("Dan", noisePublicKey));
        assertFalse(decoded.matches("Ana", new byte[32]));
    }

    @Test
    void modifiedCertificateSignatureIsRejected() throws Exception {
        KeyPair authority = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        IdentityCertificate certificate = IdentityCertificate.issue("Ana", new byte[32], authority.getPrivate());
        byte[] encoded = certificate.encode();
        encoded[encoded.length - 1] ^= 1;

        assertFalse(IdentityCertificate.decode(encoded).verify(authority.getPublic()));
    }
}
