package rkb.crypto.utils;

import org.apache.commons.lang.StringUtils;
import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 *  Utility class to generate HmacSHA/HmacMD5 hashes
 */
public class MacUtils {
    /**
     * Generates HmacSHA[n]/HmacMD5 hashes for the supplied data based on key and algorithm
     * @param algorithm
     * @param key
     * @param payload
     * @return
     */
    public static String generateMac(MacAlgorithm algorithm, String key, String payload) {
        if (StringUtils.isBlank(key) || StringUtils.isBlank(payload)) {
            return StringUtils.EMPTY;
        } else {
            return generateMac(algorithm, key, payload.getBytes());
        }
    }

    /**
     * Generates HmacSHA[n]/HmacMD5 hashes for the supplied data based on key and algorithm
     * @param algorithm
     * @param key
     * @param payload
     * @return
     */
    public static String generateMac(MacAlgorithm algorithm, String key, byte[] payload) {
        if (StringUtils.isBlank(key) || payload == null) {
            return StringUtils.EMPTY;
        } else {
            try {
                Mac mac = Mac.getInstance(algorithm.name());
                SecretKey secret = new SecretKeySpec(key.getBytes(), mac.getAlgorithm());
                mac.init(secret);
                mac.update(payload);
                return new BASE64Encoder().encode(mac.doFinal());
            } catch (GeneralSecurityException e) {
                throw new CryptoException(e);
            }
        }
    }

    /**
     * List of mac algorithms supported
     */
    public enum MacAlgorithm {
        HmacMD5, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512
    }
}