package rkb.crypto.utils;

/**
 * Generic Exception for all crypto related failures
 *
 * User: rameshb
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public CryptoException(Throwable t) {
        super(t);
    }
}
