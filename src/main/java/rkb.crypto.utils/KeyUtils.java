package rkb.crypto.utils;

//import sun.misc.BASE64Encoder;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

/**
 * Utility to generate keys/keypairs for various algorithms
 *
 * User: rameshb
 */
public class KeyUtils {
    /**
     * List of keypair algorithms supported
     */
    public enum KeyPairAlgorithm {
        RSA, DSA, DiffieHellman
    }

    /**
     * List of key algorithms supported
     */
    public enum KeyAlgorithm {
        HmacMD5, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512, AES
    }

    /**
     * Generates  keypair for algorithm and size supplied. Validate if the size
     * being sent is supported by the algorithm. If not supported, will throw
     * an exception
     * @param algorithm
     * @param size
     * @return
     */
    public static String[] generateKeyPair(KeyPairAlgorithm algorithm, int size) {
        try {
            String[] keys = new String[2];
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm.name());
            keyGen.initialize(size);
            KeyPair keypair = keyGen.genKeyPair();
            PrivateKey privateKey = keypair.getPrivate();
            PublicKey publicKey = keypair.getPublic();
            keys[0] = Base64.encodeBase64String(publicKey.getEncoded());
            keys[1] = Base64.encodeBase64String(privateKey.getEncoded());
            return keys;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Generates  key for algorithm and size supplied. Validate if the size
     * being sent is supported by the algorithm. If not supported, will throw
     * an exception
     * @param algorithm
     * @param size
     * @return
     */
    public static String generateKey(KeyAlgorithm algorithm, int size) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(algorithm.name());
            SecureRandom random = new SecureRandom();
            random.setSeed(System.currentTimeMillis());
            generator.init(size, random);
            SecretKey key = generator.generateKey();
            return Base64.encodeBase64String(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }
}
