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
public class TestAESUtils {

    private static final Logger log = LoggerFactory.getLogger(TestAESUtils.class);

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void encryptDecrypt() {
        String plainText = "rameshb|20120101221011|admin,manager,auditor|10.22.64.124";
        String encryptedText = AESUtils.encrypt(plainText);
        String decryptedText = AESUtils.decrypt(encryptedText);
        log.debug(encryptedText);
        log.debug(plainText);
        log.debug(decryptedText);
        Assert.assertEquals(plainText, AESUtils.decrypt(encryptedText));
    }
    @Test
    public void testEncryptBlankText() {
        String x = AESUtils.encrypt(StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(x));
    }
    @Test
    public void testDecryptBlankText() {
        String x = AESUtils.decrypt(StringUtils.EMPTY);
        Assert.assertTrue(StringUtils.isBlank(x));
    }
    @Test
    public void testDecryptFailure() {
        exception.expect(CryptoException.class);
        String decryptedText = AESUtils.decrypt("abcdefghijklmnopqrstuvwxyz1234567890");
    }
    @Test
    public void testEncryptNull() {
        Assert.assertEquals(StringUtils.EMPTY,AESUtils.encrypt(null));
    }
    @Test
    public void testDecryptNull() {
        Assert.assertEquals(StringUtils.EMPTY, AESUtils.decrypt(null));
    }
}
