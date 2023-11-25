import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

// skeleton code for class SessionKey

class SessionKey {
    // as specified in the task description + test files:
    // the generated key should be AES

    SecretKey sk;
    String algorithm = "AES";   // in case if we want to change the algorithm in a later task

    // constructor to create a secret key of a given length
    public SessionKey(Integer size) throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(algorithm);
        kg.init(size);
        sk = kg.generateKey();
    }

    // constructor to create a secret key from key material given as a byte array
    public SessionKey(byte[] keybytes) throws NoSuchAlgorithmException {
        sk = new SecretKeySpec(keybytes, algorithm);
    }

    // return the secret key
    public SecretKey getSecretKey() {
        return sk;
    }

    // return the secret key encoded as a byte array
    public byte[] getKeyBytes() {
        return sk.getEncoded();
    }
}
