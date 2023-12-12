import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {

    SessionKey sk;
    IvParameterSpec iv;
    Cipher cipher;

    // constructor to create a SessionCipher from a SessionKey
    // the IV is created automatically
    public SessionCipher(SessionKey key) {
        sk = key;

        // I learned how I should handle and create IV's from this website:
        // https://www.novixys.com/blog/java-aes-example/#3_Generate_an_Initialization_Vector_IV
        byte[] initVector = new byte[128/8];
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

    // epic documentation for the Cipher class:
    // https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html

    // attach OutputStream to which encrypted data will be written
    // return result as a CipherOutputStream instance
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        // specified in the instructions:
        // AES, CTR mode, no padding
        cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // specified by the comments the professor left above the function:
        // this cipher is for encryption
        SecretKey key = sk.getSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        CipherOutputStream cos = new CipherOutputStream(os, cipher);

        return cos;
    }

    // attach InputStream from which decrypted data will be read
    // return result as a CipherInputStream instance
    CipherInputStream openDecryptedInputStream(InputStream is) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey key = sk.getSecretKey();
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        CipherInputStream cis = new CipherInputStream(is, cipher);

        return cis;
    }
}
