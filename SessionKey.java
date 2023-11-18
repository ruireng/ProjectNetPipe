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
        key = new byte[length/8];
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

    public static void main(String[] args) {
        SessionKey nyckel = new SessionKey(128);
        byte[] byteArray = nyckel.getKeyBytes();


        // Loopa igenom varje byte i byte-arrayen
        int counter = 0;
        for (byte b : byteArray) {
            // Konvertera varje byte till en bitsträng och skriv ut
            String bitString = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
            System.out.print(bitString);
            counter++;
        }
        System.out.println();
        System.out.println("amount of bits: " + counter * 8);
    }
}
