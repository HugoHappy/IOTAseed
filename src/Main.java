import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class Main {

    private static SecretKeySpec secretKey;
    private static byte[] key;
    static final String TRYTE_ALPHABET = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static final int SEED_LEN = 81;

    private static final String secret = "";
    private static final String decryptSeed = "";

    public static void main(String[] args) {
        if ( secret == "" ) {
            System.out.println("Write down a secret!");
            return;
        }
        if ( decryptSeed != "") {
            String decryptedSeed = decrypt(decryptSeed, secret);
            System.out.println("Your decrypted seed: " + decryptedSeed);
            return;
        }
        String seed = seed();
        System.out.println("Your IOTA seed: " + seed);

        String encryptedSeed = encrypt(seed, secret);
        System.out.println("Your encrypted seed: " + encryptedSeed);
        System.out.println("Is encrypted seed valid: " + seed.equals(decrypt(encryptedSeed, secret)));

    }

    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static String seed(){

        SecureRandom sr;
        try {
            sr = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // this should not happen!
            e.printStackTrace();
            return "Failed";
        }

        // the resulting seed
        StringBuilder sb = new StringBuilder(SEED_LEN);

        for(int i = 0; i < SEED_LEN; i++) {
            int n = sr.nextInt(27);
            char c = TRYTE_ALPHABET.charAt(n);

            sb.append(c);
        }

        String seed = sb.toString();

        // clear StringBuilder just in case.
        for(int i = 0; i < sb.length(); i++) {
            sb.setCharAt(i, (char) 0);
        }

        return seed;
    }
}