public class HandshakeCrypto {

	// constructor to create an instance for encryption/decryption with a public key
	// the public key is given as a X509 certificate
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {

	}

    // constructor to create an instance for encryption/decryption with a private key
    // the private key is given as a byte array in PKCS8/DER format
	public HandshakeCrypto(byte[] keybytes) {

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