import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

// handshakeCertificate class represents X509 certificates exchanged during initial handshake
public class HandshakeCertificate {

    // constructor to create a certificate from data read on an input stream
    // the data is DER-encoded, in binary or Base64 encoding (PEM format)
    HandshakeCertificate(InputStream instream) {

    }

    // constructor to create a certificate from its encoded representation given as a byte array
    HandshakeCertificate(byte[] certbytes) {

    }

    // return the encoded representation of certificate as a byte array
    public byte[] getBytes() {
        return new byte[0];
    }

    // return the X509 certificate
    public X509Certificate getCertificate() {
        return null;
    }

    // cryptographically validate a certificate
    // throw relevant exception if validation fails
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

    }

    // return CN (Common Name) of subject
    public String getCN() {
        return null;
    }

    // return email address of subject
    public String getEmail() {
        return null;
    }
}
