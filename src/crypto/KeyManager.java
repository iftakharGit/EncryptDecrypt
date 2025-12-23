package crypto;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class KeyManager {

    private static final int RSA_BITS = 4096;
    private static final int PBKDF2_ITERS = 200_000;
    private static final int GCM_TAG_BITS = 128;

    public static void generateKeysIfMissing(char[] password) throws Exception {
        if (Files.exists(Path.of("public.key")) && Files.exists(Path.of("private.key")))
            return;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_BITS);
        KeyPair kp = kpg.generateKeyPair();

        Files.write(Path.of("public.key"), kp.getPublic().getEncoded());

        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        byte[] iv = SecureRandom.getInstanceStrong().generateSeed(12);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, 256);
        SecretKey tmp = skf.generateSecret(spec);
        SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] encryptedPrivateKey = cipher.doFinal(kp.getPrivate().getEncoded());

        try (DataOutputStream out = new DataOutputStream(new FileOutputStream("private.key"))) {
            out.writeInt(salt.length);
            out.write(salt);
            out.writeInt(iv.length);
            out.write(iv);
            out.write(encryptedPrivateKey);
        }
    }

    public static PublicKey loadPublicKey() throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(
                        Files.readAllBytes(Path.of("public.key"))));
    }

    public static PrivateKey loadPrivateKey(char[] password) throws Exception {

        try (DataInputStream in = new DataInputStream(new FileInputStream("private.key"))) {

            byte[] salt = new byte[in.readInt()];
            in.readFully(salt);

            byte[] iv = new byte[in.readInt()];
            in.readFully(iv);

            byte[] encrypted = in.readAllBytes();

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, 256);
            SecretKey tmp = skf.generateSecret(spec);
            SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(cipher.doFinal(encrypted)));
        }
    }
}