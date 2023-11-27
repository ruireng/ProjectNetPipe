import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    MessageDigest md;

    // constructor -- initialise a digest for SHA-256
    public HandshakeDigest() throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance("SHA256");
    }

    // update digest with input data
    public void update(byte[] input) {
        md.update(input);
    }

    // compute final digest
    public byte[] digest() {
        byte[] digest = md.digest();

        return digest;
    }
}
