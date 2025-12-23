package crypto;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileEncryptor {

    public static void encrypt(String input, String output, PublicKey publicKey) throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        byte[] nonce = SecureRandom.getInstanceStrong().generateSeed(12);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));

        byte[] ciphertext = aes.doFinal(Files.readAllBytes(Path.of(input)));

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsa.doFinal(aesKey.getEncoded());

        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(output))) {
            out.writeInt(encryptedKey.length);
            out.write(encryptedKey);
            out.write(nonce);
            out.write(ciphertext);
        }
    }
}