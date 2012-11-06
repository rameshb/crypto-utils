package rkb.crypto.utils;

import junit.framework.Assert;
import org.apache.commons.lang.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidParameterException;

/**
 * User: rameshb
 */
public class TestKeyUtils {

    private static final Logger log = LoggerFactory.getLogger(TestKeyUtils.class);

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testKeyPairGeneration() {
        String[] keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.RSA, 512);
        log.debug("RSA Public: " + keys[0]);
        log.debug("RSA Private: " + keys[1]);
        Assert.assertNotNull(keys);
        Assert.assertEquals(2, keys.length);
        Assert.assertNotNull(keys[0]);
        Assert.assertNotNull(keys[1]);
        log.debug("---------------------");
        keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.DSA, 512);
        log.debug("DSA Public: " + keys[0]);
        log.debug("DSA Private: " + keys[1]);
        Assert.assertNotNull(keys);
        Assert.assertEquals(2, keys.length);
        Assert.assertNotNull(keys[0]);
        Assert.assertNotNull(keys[1]);
        log.debug("---------------------");
        keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.DiffieHellman, 512);
        log.debug("DH Public: " + keys[0]);
        log.debug("DH Private: " + keys[1]);
        Assert.assertNotNull(keys);
        Assert.assertEquals(2, keys.length);
        Assert.assertNotNull(keys[0]);
        Assert.assertNotNull(keys[1]);
    }
    @Test
    public void testKeyGeneration() {
        String key = null;
        key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.AES, 256);
        Assert.assertTrue(StringUtils.isNotBlank(key));
        log.debug("AES: " + key);
        key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.HmacMD5, 256);
        Assert.assertTrue(StringUtils.isNotBlank(key));
        log.debug("HmacMD5: " + key);
        key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.HmacSHA1, 256);
        Assert.assertTrue(StringUtils.isNotBlank(key));
        log.debug("HmacSHA1: " + key);
        key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.HmacSHA256, 256);
        Assert.assertTrue(StringUtils.isNotBlank(key));
        log.debug("HmacSHA256: " + key);
        key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.HmacSHA384, 256);
        Assert.assertTrue(StringUtils.isNotBlank(key));
        log.debug("HmacSHA384: " + key);
        key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.HmacSHA512, 256);
        Assert.assertTrue(StringUtils.isNotBlank(key));
        log.debug("HmacSHA512: " + key);
    }
    @Test
    public void testWrongKeySizeWithKeyPairs() {
        exception.expect(InvalidParameterException.class);
        String[] keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.RSA, 64);
    }

    @Test
    public void testWrongKeySizeWithKeys() {
        exception.expect(InvalidParameterException.class);
        String key = KeyUtils.generateKey(KeyUtils.KeyAlgorithm.AES, 64);
    }
}
