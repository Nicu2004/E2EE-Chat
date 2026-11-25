package org.example;



import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.*;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

public record Identity(String name, KeyPair keyPair) {

    private static final String regex = "[A-Za-z_]{1,32}";
    private static final Pattern p = Pattern.compile(regex);


    public static Identity loadOrStoreIdentity(String name, Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {


        Properties properties = new Properties();
        if(!(p.matcher(name)).matches())
            throw new IllegalArgumentException("exception ");
        Path file = path.resolve(name).resolve("identity.properties");
        if(Files.exists(file))
        {
            try(Reader inputStream = Files.newBufferedReader(file, StandardCharsets.UTF_8))
            {
                properties.load(inputStream);
                if(properties.getProperty("publicKey")==null || properties.getProperty("privateKey")==null)
                    throw new InvalidObjectException("Invalid file reading data");
                byte[] pubKeyBytes = Base64.getDecoder().decode(properties.getProperty("publicKey"));
                byte[] prvKeyBytes = Base64.getDecoder().decode(properties.getProperty("privateKey"));
                PublicKey pk = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pubKeyBytes));
                PrivateKey pv = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(prvKeyBytes));
                KeyPair keyPair = new KeyPair(pk, pv);
                return new Identity(name, keyPair);

            }
        }
        else{//save the key pair
            Files.createDirectories(file.getParent());
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            try(Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
                properties.setProperty("publicKey", pub);
                String prv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
                properties.setProperty("privateKey", prv);
                properties.store(w, name);
                return new Identity(name, kp);
            }
        }
    }


}
