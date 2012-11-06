package rkb.crypto.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility to generate hashes using various algorithms
 *
 * User: rameshb
 */
public class HashUtils {

    /**
     * Generates a hash using the algorithm specified for the supplied payload. The generated hash is encoded in
     * the format provided
     * @param algorithm
     * @param payload
     * @param encoding
     * @return
     */
    public static String generateHash(HashAlgorithm algorithm, String payload, HashEncoding encoding) {
        if (StringUtils.isBlank(payload)) {
            return StringUtils.EMPTY;
        } else {
            return generateHash(algorithm, payload.getBytes(), encoding);
        }
    }

    /**
     * Generates a hash using the algorithm specified for the supplied payload. The generated hash is encoded in
     * the format provided
     * @param algorithm
     * @param payload
     * @param encoding
     * @return
     */
    public static String generateHash(HashAlgorithm algorithm, byte[] payload, HashEncoding encoding) {
        if (payload != null) {
            try {
                MessageDigest digest = MessageDigest.getInstance(algorithm.toString());
                digest.update(payload);
                switch (encoding) {
                    case BASE64:
                        return Base64.encodeBase64String(digest.digest());
                    case HEX:
                        return Hex.encodeHexString(digest.digest());
                    default:
                        return Base64.encodeBase64String(digest.digest());
                }
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(e);
            }
        } else {
            return StringUtils.EMPTY;
        }
    }

    /**
     * List of encoding methods supported
     */
    public enum HashEncoding {
        BASE64, HEX
    }

    /**
     * List of hashing algorithms supported
     */
    public enum HashAlgorithm {
        MD2("MD2"), MD5("MD5"), SHA1("SHA-1"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512");

        private String algorithm;

        HashAlgorithm(final String name) {
            this.algorithm = name;
        }

        public String toString() {
            return this.algorithm;
        }

    }

}
