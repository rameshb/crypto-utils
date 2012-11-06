package rkb.crypto.utils;

import junit.framework.Assert;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;

/**
 * User: rameshb
 */
public class TestMacUtils {

    private static final Logger log = LoggerFactory.getLogger(TestMacUtils.class);

    final String payload = "quick brown fox jumped over the lazy dog";

    @Test
    public void testMac() {
        String macHash = null;
        SecureRandom srnd = new SecureRandom();
        srnd.setSeed(System.currentTimeMillis());
        byte[] b = new byte[32];
        srnd.nextBytes(b);
        String key = Base64.encodeBase64String(b);


        macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacMD5, key, payload);
        Assert.assertTrue(StringUtils.isNotBlank(macHash));
        log.debug("HmacMD5: " + macHash);

        macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA1, key, payload);
        Assert.assertTrue(StringUtils.isNotBlank(macHash));
        log.debug("HmacSHA1: " + macHash);

        macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA256, key, payload);
        Assert.assertTrue(StringUtils.isNotBlank(macHash));
        log.debug("HmacSHA256: " + macHash);

        macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA384, key, payload);
        Assert.assertTrue(StringUtils.isNotBlank(macHash));
        log.debug("HmacSHA384: " + macHash);

        macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA512, key, payload);
        Assert.assertTrue(StringUtils.isNotBlank(macHash));
        log.debug("HmacSHA512: " + macHash);
    }

    @Test
    public void testBadKey() {
        String macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA512, "123", payload);
        Assert.assertTrue(StringUtils.isNotBlank(macHash));
        log.debug("HmacSHA512: " + macHash);
    }
    @Test
    public void testEmptyKey() {
        String macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA512, StringUtils.EMPTY, payload);
        Assert.assertTrue(StringUtils.isBlank(macHash));
    }
    @Test
    public void testEmptyPayload() {
        String macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA512, "123", StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(macHash));
    }
    @Test
    public void testEmptyPayloadAndKey() {
        String macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA512, StringUtils.EMPTY, StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(macHash));
    }
    @Test
    public void testNullKey() {
        String macHash = MacUtils.generateMac(MacUtils.MacAlgorithm.HmacSHA512, null, StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(macHash));
    }
}
