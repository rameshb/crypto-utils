package rkb.crypto.utils;

import junit.framework.Assert;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User: rameshb
 */
public class TestHashUtils {

    private static final Logger log = LoggerFactory.getLogger(TestHashUtils.class);

    @Test
    public void testHash() {
        String hash = null;
        final String payload = "quick brown fox jumped over the lazy dog";

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.MD2, payload, HashUtils.HashEncoding.BASE64);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("MD2 Base64: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.MD2, payload, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("MD2 HEX: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.MD5, payload, HashUtils.HashEncoding.BASE64);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("MD5 Base64: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.MD5, payload, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("MD5 HEX: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA1, payload, HashUtils.HashEncoding.BASE64);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA1 Base64: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA1, payload, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA1 HEX: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA256, payload, HashUtils.HashEncoding.BASE64);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA256 Base64: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA256, payload, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA256 HEX: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA384, payload, HashUtils.HashEncoding.BASE64);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA384 Base64: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA384, payload, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA384 HEX: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA512, payload, HashUtils.HashEncoding.BASE64);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA512 Base64: " + hash);

        hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA512, payload, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isNotBlank(hash));
        log.debug("SHA512 HEX: " + hash);

    }
    @Test
    public void testEmptyHash() {
        String hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA512, StringUtils.EMPTY, HashUtils.HashEncoding.HEX);
        Assert.assertTrue(StringUtils.isBlank(hash));
    }

    @Test
    public void testEmptyByteArray() {
        String hash = HashUtils.generateHash(HashUtils.HashAlgorithm.SHA512, new byte[0], HashUtils.HashEncoding.HEX);
        Assert.assertNotNull(hash);
    }
}
