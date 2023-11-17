import javax.crypto.SecretKey;
import java.security.SecureRandom;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    SecretKey sk;
    byte[] key;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) {
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(key);
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        key = keybytes;
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return sk;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return key;
    }
}