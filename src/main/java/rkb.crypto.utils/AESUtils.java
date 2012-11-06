package rkb.crypto.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * Utility class to perform AES encryption and decryption.
 *
 * @author : rameshb
 */
public class AESUtils {

    private static Cipher encryptCipher;
    private static Cipher decryptCipher;
    private static SecretKey secret;
    private static byte[] ivParams;

    private static final String KEY_TYPE = "PBKDF2WithHmacSHA1";
    private static final String ENCRYPTION = "AES";
    private static final String CIPHER_TYPE = "AES/CBC/PKCS5Padding";

    private static final String ENCODING = "UTF-16";

    private static char[] password;
    private static byte[] salt;

    static {
        try {
            //Generate key for encryption mechanism
            salt = new byte[8];
            password = new char[16];
            //Generate a salt using current time in milliseconds to reduce predictability
            SecureRandom random = new SecureRandom();
            random.setSeed(System.currentTimeMillis());
            random.nextBytes(salt);
            //Generate a password using current time in milliseconds
            random = new SecureRandom();
            random.setSeed(System.currentTimeMillis());
            byte[] pwdBytes = new byte[16];
            random.nextBytes(pwdBytes);
            password = new String(pwdBytes, ENCODING).toCharArray();
            //use salt and password to generate the secret key
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_TYPE);
            KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secret = new SecretKeySpec(tmp.getEncoded(), ENCRYPTION);
            //initialize a cipher in encryption mode
            encryptCipher = Cipher.getInstance(CIPHER_TYPE);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secret);
            ivParams = encryptCipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            //initialize a cipher in decryption mode
            decryptCipher = Cipher.getInstance(CIPHER_TYPE);
            decryptCipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivParams));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Encrypts the given string using AES with a generated password and salt. Returns the
     * encrypted text in Base64 encoded format
     * @param plainText
     * @return
     */
    public static String encrypt(String plainText) {
        try {
            if (StringUtils.isNotBlank(plainText)) {
                return Base64.encodeBase64String(encryptCipher.doFinal(plainText.getBytes(ENCODING)));
            } else {
                return StringUtils.EMPTY;
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        } catch (UnsupportedEncodingException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Decrypts the given string previously encrypted using AES. Expects the encrypted text to
     * be in Base64 encoded format
     * @param encryptedText
     * @return
     */
    public static String decrypt(String encryptedText) {
        try {
            if (StringUtils.isNotBlank(encryptedText)) {
                byte[] decryptedBytes = decryptCipher.doFinal(Base64.decodeBase64(encryptedText));
                return new String(decryptedBytes, ENCODING);
            } else {
                return StringUtils.EMPTY;
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        } catch (IOException e) {
            throw new CryptoException(e);
        }
    }

}
