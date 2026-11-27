package org.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.southernstorm.noise.protocol.DHState;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IdentityAuthorityTest {
    @Test
    void issuesCertificateForPersistentNoiseIdentity(@TempDir Path home) throws Exception {
        String originalHome = System.getProperty("user.home");
        System.setProperty("user.home", home.toString());
        try {
            IdentityAuthority.initialize();
            IdentityAuthority.issueCertificate("Ana");

            IdentityCertificate certificate = IdentityAuthority.loadCertificate("Ana");
            DHState identity = ChatClient.loadOrCreateNoiseIdentity("Ana");
            byte[] publicKey = new byte[identity.getPublicKeyLength()];
            try {
                identity.getPublicKey(publicKey, 0);
            } finally {
                identity.destroy();
            }

            assertTrue(certificate.verify(IdentityAuthority.loadAuthorityPublicKey()));
            assertTrue(certificate.matches("Ana", publicKey));
            assertFalse(certificate.matches("Dan", publicKey));
        } finally {
            if (originalHome == null) System.clearProperty("user.home");
            else System.setProperty("user.home", originalHome);
        }
    }
}
