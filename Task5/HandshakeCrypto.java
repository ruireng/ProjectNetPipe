import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

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
    public byte[] decrypt(byte[] ciphertext) {
		return new byte[0];
    }

    // encrypt byte array with the key, return result as a byte array
    public byte [] encrypt(byte[] plaintext) {
		return new byte[0];
    }
}
