import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

// handshakeCertificate class represents X509 certificates exchanged during initial handshake
public class HandshakeCertificate {

    X509Certificate cert;

    // constructor to create a certificate from data read on an input stream
    // the data is DER-encoded, in binary or Base64 encoding (PEM format)
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(instream);
    }

    // constructor to create a certificate from its encoded representation given as a byte array
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certbytes));
    }

    // return the encoded representation of certificate as a byte array
    public byte[] getBytes() throws CertificateEncodingException {
        return cert.getEncoded();
    }

    // return the X509 certificate
    public X509Certificate getCertificate() {
        return cert;
    }

    // cryptographically validate a certificate
    // throw relevant exception if validation fails
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        cert.verify(cacert.getCertificate().getPublicKey());
    }

    // return CN (Common Name) of subject
    public String getCN() {
        X500Principal subjectInfo = cert.getSubjectX500Principal();
        
        return null;
    }

    // return email address of subject
    public String getEmail() {
        return null;
    }
}
