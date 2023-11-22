import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    SessionKey sk;
    IvParameterSpec iv;

    // constructor to create a SessionCipher from a SessionKey
    // the IV is created automatically
    public SessionCipher(SessionKey key) {
        sk = key;
        int keyLength = key.getKeyBytes().length;

        // I learned how I should handle and create IV's from this website:
        // https://www.novixys.com/blog/java-aes-example/#3_Generate_an_Initialization_Vector_IV
        byte[] initVector = new byte[keyLength];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(initVector);
        iv = new IvParameterSpec(initVector);
    }

    // constructor to create a SessionCipher from a SessionKey and an IV, given as a byte array
    public SessionCipher(SessionKey key, byte[] ivbytes) {
        sk = key;
        iv = new IvParameterSpec(ivbytes);
    }

    // return the SessionKey
    public SessionKey getSessionKey() {
        return sk;
    }

    // return the IV as a byte array
    public byte[] getIVBytes() {
        return iv.getIV();
    }

    // attach OutputStream to which encrypted data will be written
    // return result as a CipherOutputStream instance
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        
        CipherOutputStream cos = new CipherOutputStream(os, null);

        return cos;
    }

    // attach InputStream from which decrypted data will be read
    // return result as a CipherInputStream instance
    CipherInputStream openDecryptedInputStream(InputStream is) {
        CipherInputStream cis = new CipherInputStream(is, null);

        return cis;
    }
}