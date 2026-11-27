package org.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

final class IdentityCertificate {
    private static final int MAGIC = 0x43454531;
    private static final int NOISE_KEY_LENGTH = 32;
    private static final int SIGNATURE_LENGTH = 64;

    private final String name;
    private final byte[] noisePublicKey;
    private final byte[] signature;

    private IdentityCertificate(String name, byte[] noisePublicKey, byte[] signature) {
        this.name = name;
        this.noisePublicKey = noisePublicKey.clone();
        this.signature = signature.clone();
    }

    static IdentityCertificate issue(String name, byte[] noisePublicKey, PrivateKey caPrivateKey)
            throws GeneralSecurityException, IOException {
        validateName(name);
        if (noisePublicKey.length != NOISE_KEY_LENGTH) {
            throw new IOException("Cheia publica Noise trebuie sa aiba 32 de octeti.");
        }
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(caPrivateKey);
        signer.update(signedData(name, noisePublicKey));
        return new IdentityCertificate(name, noisePublicKey, signer.sign());
    }

    static IdentityCertificate decode(byte[] encoded) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readInt() != MAGIC) {
                throw new IOException("Format de certificat Noise necunoscut.");
            }
            String name = input.readUTF();
            validateName(name);
            int keyLength = input.readInt();
            if (keyLength != NOISE_KEY_LENGTH) {
                throw new IOException("Lungime invalida a cheii Noise din certificat.");
            }
            byte[] publicKey = input.readNBytes(keyLength);
            int signatureLength = input.readInt();
            if (publicKey.length != keyLength || signatureLength != SIGNATURE_LENGTH) {
                throw new IOException("Certificat incomplet sau invalid.");
            }
            byte[] signature = input.readNBytes(signatureLength);
            if (signature.length != signatureLength || input.read() != -1) {
                throw new IOException("Certificat incomplet sau cu date suplimentare.");
            }
            return new IdentityCertificate(name, publicKey, signature);
        } catch (IllegalArgumentException e) {
            throw new IOException("Nume invalid in certificatul Noise.", e);
        }
    }

    byte[] encode() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC);
            output.writeUTF(name);
            output.writeInt(noisePublicKey.length);
            output.write(noisePublicKey);
            output.writeInt(signature.length);
            output.write(signature);
        }
        return bytes.toByteArray();
    }

    boolean verify(PublicKey caPublicKey) throws GeneralSecurityException, IOException {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(caPublicKey);
        verifier.update(signedData(name, noisePublicKey));
        return verifier.verify(signature);
    }

    boolean matches(String expectedName, byte[] expectedPublicKey) {
        return name.equals(expectedName) && MessageDigest.isEqual(noisePublicKey, expectedPublicKey);
    }

    String name() {
        return name;
    }

    private static byte[] signedData(String name, byte[] noisePublicKey) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeUTF("CHAT_E2EE_NOISE_IDENTITY_V1");
            output.writeUTF(name);
            output.writeInt(noisePublicKey.length);
            output.write(noisePublicKey);
        }
        return bytes.toByteArray();
    }

    private static void validateName(String name) {
        if (name == null || !name.matches("[A-Za-z0-9_]{1,32}")) {
            throw new IllegalArgumentException("Numele poate contine doar litere, cifre si underscore.");
        }
    }
}
