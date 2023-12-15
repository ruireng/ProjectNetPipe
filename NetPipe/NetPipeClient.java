import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import java.io.*;

public class NetPipeClient {
    
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    // usage: explain how to use the program, then exit with failure status
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");

        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");

        System.exit(1);
    }

    // parse arguments on command line
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "filename");
        arguments.setArgumentSpec("cacert", "filename");
        arguments.setArgumentSpec("key", "filename");

        try {
        arguments.loadArguments(args);
        }
        catch(IllegalArgumentException iae) {
            usage();
        }
    }

    // initiate certificate
    private static HandshakeCertificate initCert(String pathName) {
        try {
            FileInputStream fis = new FileInputStream(pathName);
            HandshakeCertificate hc = new HandshakeCertificate(fis);

            return hc;
        }
        catch(FileNotFoundException fnfe) {
            System.err.printf("Cannot find file %s\n", pathName);

            return null;
        }
        catch(CertificateException ce) {
            System.err.printf("Error initiating certificate %s\n", pathName);

            return null;
        }
    }

    // initiate private key
    private static byte[] initKey(String pathName) {
        try {
            FileInputStream fis = new FileInputStream(pathName);
            byte[] PKBytes = fis.readAllBytes();
            fis.close();

            return PKBytes;
        }
        catch(FileNotFoundException fnfe) {
            System.err.printf("Cannot find file %s\n", pathName);

            return null;
        }
        catch(IOException ioe) {
            System.err.printf("Error reading private key %s\n", pathName);

            return null;
        }
    }

    // verify CA certificate
    private static void verifyCACert(HandshakeCertificate CA) {
        try {
            if(!(CA.getCN().equals("ca-np.ik2206.kth.se"))) {
                throw new CertificateException();
            }
            CA.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying CA certificate");
            System.exit(1);
        }
    }

    // verify client certificate against CA
    private static void verifyClientCert(HandshakeCertificate client, HandshakeCertificate CA) {
        try {
            if(!(client.getCN().equals("client-np.ik2206.kth.se"))) {
                throw new CertificateException();
            }
            client.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying client certificate");
            System.exit(1);
        }
    }

    // verify server certificate against CA
    private static void verifyServerCert(HandshakeCertificate server, HandshakeCertificate CA) {
        try {
            if(!(server.getCN().equals("server-np.ik2206.kth.se"))) {
                throw new CertificateException();
            }
            server.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying server certificate\n");
            System.exit(1);
        }
    }

    // initiate socket
    private static Socket initSocket(String host, int port) {
        try {
            Socket socket = new Socket(host, port);

            return socket;
        }
        catch(IOException ioe) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            
            return null;
        }
    }

    // send ClientHello message
    private static void sendClientHello(Socket socket, HandshakeCertificate usercert) {
        HandshakeMessage hm = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        try {
            X509Certificate cert = usercert.getCertificate();
            byte[] certBytes = cert.getEncoded();
            String encodedCert = Base64.getEncoder().encodeToString(certBytes);
            hm.put("Certificate", encodedCert);
            hm.send(socket);
        }
        catch(CertificateEncodingException cee) {
            System.err.printf("Error getting encoded certificate\n");
            System.exit(1);
        }
        catch(IOException ioe) {
            System.err.printf("Error sending ClientHello\n");
            System.exit(1);
        }
    }

    // receive ServerHello and verify server certificate
    private static HandshakeCertificate recvServerHello(Socket socket, HandshakeCertificate CA) {
        try {
            HandshakeMessage hm = HandshakeMessage.recv(socket);
            if(hm.getType().getCode() != 2) {
                throw new IOException();
            }
            String encodedCert = hm.getParameter("Certificate");
            byte[] decodedCert = Base64.getDecoder().decode(encodedCert);
            HandshakeCertificate serverCert = new HandshakeCertificate(decodedCert);
            verifyServerCert(serverCert, CA);

            return serverCert;
        }
        catch(IOException | ClassNotFoundException e) {
            System.err.printf("Error receiving ServerHello from server\n");

            return null;
        }
        catch(CertificateException ce) {
            System.err.printf("Error reading server certificate\n");

            return null;
        }
    }

    // send Session message
    private static SessionCipher sendSession(Socket socket, HandshakeCertificate serverCert) {
        HandshakeMessage hm = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        HandshakeCrypto hc = new HandshakeCrypto(serverCert);
        try {
            SessionKey sk = new SessionKey(128);
            SessionCipher sc = new SessionCipher(sk);
            byte[] SKBytes = sk.getKeyBytes();
            byte[] IVBytes = sc.getIVBytes();
            SKBytes = hc.encrypt(SKBytes);
            IVBytes = hc.encrypt(IVBytes);
            String encodedSK = Base64.getEncoder().encodeToString(SKBytes);
            String encodedIV = Base64.getEncoder().encodeToString(IVBytes);
            hm.put("SessionKey", encodedSK);
            hm.put("SessionIV", encodedIV);
            hm.send(socket);

            return sc;
        }
        catch(NoSuchAlgorithmException nsae) {
            System.err.printf("Error creating session key\n");

            return null;
        }
        catch(NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.printf("Error encrypting session message\n");

            return null;
        }
        catch(IOException ioe) {
            System.err.printf("Error sending Session\n");

            return null;
        }
    }

    // main program
    // parse arguments on command line, connect to server,
    // and call forwarder to forward data between streams
    public static void main(String[] args) {
        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));        
        String usercertPath = arguments.get("usercert");
        String cacertPath = arguments.get("cacert");
        String privatekeyPath = arguments.get("key");

        HandshakeCertificate clientCert = initCert(usercertPath);
        HandshakeCertificate caCert = initCert(cacertPath);
        if(clientCert == null || caCert == null) {
            System.exit(1);
        }
        verifyCACert(caCert);
        verifyClientCert(clientCert, caCert);
        byte[] key = initKey(privatekeyPath);
        if(key == null) {
            System.exit(1);
        }

        Socket socket = initSocket(host, port);
        if(socket == null) {
            System.exit(1);
        }
        
        // use HandshakeMessage to send CLIENTHELLO to server
        sendClientHello(socket, clientCert);
        System.out.println("sent ClientHello");
        // wait for SERVERHELLO
        HandshakeCertificate serverCert = recvServerHello(socket, caCert);
        if(serverCert == null) {
            System.exit(1);
        }
        System.out.println("received ServerHello");
        // use HandshakeCertificate to verify server's certificate
        // send SESSION to server
        SessionCipher sessionCipher = sendSession(socket, serverCert);
        if(sessionCipher == null) {
            System.exit(1);
        }
        //System.out.println("sent Session");
        // wait for SERVERFINISHED
        // send CLIENTFINISHED
        try {
            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}