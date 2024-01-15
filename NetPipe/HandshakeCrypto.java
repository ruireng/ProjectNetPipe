import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HandshakeCrypto {

    boolean certificate;
    PublicKey pubkey;
    PrivateKey prikey;

	// constructor to create an instance for encryption/decryption with a public key
	// the public key is given as a X509 certificate
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
        certificate = true;
        pubkey = handshakeCertificate.getCertificate().getPublicKey();
        prikey = null;
	}

    // constructor to create an instance for encryption/decryption with a private key
    // the private key is given as a byte array in PKCS8/DER format
	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        // useful recommendation by our professor:
        // https://stackoverflow.com/questions/20119874/how-to-load-the-private-key-from-a-der-file-into-java-private-key-object
        
        certificate = false;
        pubkey = null;
        
        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(keybytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        prikey = kf.generatePrivate(pkcs8);
	}

    // decrypt byte array with the key, return result as a byte array
    public byte[] decrypt(byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        if(certificate) {
            cipher.init(Cipher.DECRYPT_MODE, pubkey);
        }
        else {
            cipher.init(Cipher.DECRYPT_MODE, prikey);
        }   
        byte[] plaintext = cipher.doFinal(ciphertext);

    	return plaintext;
    }

    // encrypt byte array with the key, return result as a byte array
    public byte [] encrypt(byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        if(certificate) {
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        }
        else {
            cipher.init(Cipher.ENCRYPT_MODE, prikey);
        }   
        byte[] ciphertext = cipher.doFinal(plaintext);  
    	
        return ciphertext;
    }
}
