import crypto.*;

public class Main {

    private static final char[] PASSWORD =
            "YourPasswordHere".toCharArray();

    public static void main(String[] args) throws Exception {

        KeyManager.generateKeysIfMissing(PASSWORD);

        FileEncryptor.encrypt(
                "CryptoSeedPhrase.txt",
                "CryptoSeedPhrase.txt.enc",
                KeyManager.loadPublicKey()
        );

        FileDecryptor.decrypt(
                "CryptoSeedPhrase.txt.enc",
                "CryptoSeedPhrase_decrypted.txt",
                KeyManager.loadPrivateKey(PASSWORD)
        );

        System.out.println("Encryption & decryption completed securely.");
    }
}