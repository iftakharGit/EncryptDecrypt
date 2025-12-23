package crypto;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileDecryptor {

    public static void decrypt(String input, String output, PrivateKey privateKey) throws Exception {

        try (DataInputStream in = new DataInputStream(new FileInputStream(input))) {

            byte[] encryptedKey = new byte[in.readInt()];
            in.readFully(encryptedKey);

            byte[] nonce = new byte[12];
            in.readFully(nonce);

            byte[] ciphertext = in.readAllBytes();

            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
            rsa.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] aesKeyBytes = rsa.doFinal(encryptedKey);

            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"),
                    new GCMParameterSpec(128, nonce));

            Files.write(Path.of(output), aes.doFinal(ciphertext));
        }
    }
}