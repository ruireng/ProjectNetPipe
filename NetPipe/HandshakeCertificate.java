import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

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
        // got a lot of help from this forum:
        // https://stackoverflow.com/questions/2914521/how-to-extract-cn-from-x509certificate-in-java

        String dn = cert.getSubjectX500Principal().toString();
        try {
            LdapName ln = new LdapName(dn);
            for(Rdn rdn : ln.getRdns()) {
                if(rdn.getType().equals("CN")) {
                    return rdn.getValue().toString();
                }
            }

            return null;
        }
        catch(InvalidNameException ine) {
            return null;
        }
    }

    // return email address of subject
    public String getEmail() {
        String dn = cert.getSubjectX500Principal().toString();
        try {
            LdapName ln = new LdapName(dn);
            for(Rdn rdn : ln.getRdns()) {
                if(rdn.getType().equals("EMAILADDRESS")) {
                    return rdn.getValue().toString();
                }
            }

            return null;
        }
        catch(InvalidNameException ine) {
            return null;
        }
    }
}