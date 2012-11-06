package rkb.crypto.utils;

import junit.framework.Assert;
import org.apache.commons.lang.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User: rameshb
 */
public class TestRSAUtils {

    private static final Logger log = LoggerFactory.getLogger(TestRSAUtils.class);

    final String content = "the quick brown fox jump over the lazy dog";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testRSA() {
        String encryptedText;
        String decryptedText;
        String[] keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.RSA, 512);
        log.debug("RSA Data: " + content);
        encryptedText = RSAUtils.encrypt(keys[0], content);
        Assert.assertTrue(StringUtils.isNotBlank(encryptedText));
        log.debug("RSA Encrypted Data: " + encryptedText);
        decryptedText = RSAUtils.decrypt(keys[1], encryptedText);
        Assert.assertTrue(StringUtils.isNotBlank(decryptedText));
        log.debug("RSA Decrypted Data: " + decryptedText);
        Assert.assertEquals(content, decryptedText);
    }
    @Test
    public void testEmptyPublicKey() {
        String data = RSAUtils.encrypt(StringUtils.EMPTY, content);
        Assert.assertTrue(StringUtils.isBlank(data));
    }
    @Test
    public void testEmptyPrivateKey() {
        String data = RSAUtils.decrypt(StringUtils.EMPTY, content);
        Assert.assertTrue(StringUtils.isBlank(data));
    }
    @Test
    public void testEmptyContentEncrypt() {
        String[] keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.RSA, 512);
        String data = RSAUtils.encrypt(keys[0], StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(data));
    }
    @Test
    public void testEmptyContentDecrypt() {
        String[] keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.RSA, 512);
        String data = RSAUtils.decrypt(keys[1], StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(data));
    }
    @Test
    public void testEmptyPublicKeyAndContent() {
        String data = RSAUtils.encrypt(StringUtils.EMPTY, StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(data));
    }
    @Test
    public void testEmptyPrivateKeyAndContent() {
        String data = RSAUtils.decrypt(StringUtils.EMPTY, StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(data));
    }
    @Test
    public void testBadPublicKey() {
        exception.expect(CryptoException.class);
        String data = RSAUtils.encrypt("123", content);
    }
    @Test
    public void testBadPrivateKey() {
        exception.expect(CryptoException.class);
        String data = RSAUtils.encrypt("123", content);
    }

    @Test
    public void testBadEncodedContentDecrypt() {
        String[] keys = KeyUtils.generateKeyPair(KeyUtils.KeyPairAlgorithm.RSA, 512);
        exception.expect(CryptoException.class);
        String data = RSAUtils.decrypt(keys[1], content);
    }
}
