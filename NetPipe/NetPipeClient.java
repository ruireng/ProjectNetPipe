import java.net.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class NetPipeClient {
    
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    private static byte[] ClientHello = null;
    private static byte[] ServerHello = null;
    private static byte[] Session = null;

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
            ClientHello = hm.getBytes();

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
            ServerHello = hm.getBytes();

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

    // send Session message and get session key + IV
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
            Session = hm.getBytes();
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

    // receive ServerFinished message and check integrity and authentication of handshake
    private static void recvServerFinished(Socket socket, HandshakeCertificate serverCert) {
        HandshakeCrypto hc = new HandshakeCrypto(serverCert);
        try {
            HandshakeMessage hm = HandshakeMessage.recv(socket);
            if(hm.getType().getCode() != 5) {
                throw new IOException();
            }

            LocalDateTime clientLDT = LocalDateTime.now();
            String encodedServerTD = hm.getParameter("TimeStamp");
            byte[] decodedServerTD = Base64.getDecoder().decode(encodedServerTD);
            decodedServerTD = hc.decrypt(decodedServerTD);
            String serverTD = new String(decodedServerTD, StandardCharsets.UTF_8);
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            LocalDateTime serverLDT = LocalDateTime.parse(serverTD, dtf);
            Duration duration = Duration.between(serverLDT, clientLDT);
            long secondsDiff = duration.getSeconds();
            if(Math.abs(secondsDiff) > 10) {
                throw new DateTimeException("");
            }

            HandshakeDigest hd = new HandshakeDigest();
            String encodedSign = hm.getParameter("Signature");
            byte[] decodedSign = Base64.getDecoder().decode(encodedSign);
            byte[] serverDigest = hc.decrypt(decodedSign);
            hd.update(ServerHello);
            byte[] localDigest = hd.digest();
            if(!(Arrays.equals(localDigest, serverDigest))) {
                throw new ArrayStoreException(); // might be bad programming but I want a unique Exception to catch
            }
        }
        catch(IOException | ClassNotFoundException e) {
            System.err.printf("Error receiving ServerFinished from server\n");
            System.exit(1);
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.printf("Error decrypting ServerFinished from server\n");
            System.exit(1);
        }
        catch(DateTimeException dte) {
            System.err.printf("ServerFinished message too old (10 seconds)\n");
            System.exit(1);
        }
        catch(ArrayStoreException ase) {
            System.err.printf("Integrity check failed\n");
            System.exit(1);
        }
    }

    // send ClientFinished message
    private static void sendClientFinished(Socket socket, byte[] privateKey) {
        HandshakeMessage hm = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        try {
            HandshakeDigest hd = new HandshakeDigest();
            HandshakeCrypto hc = new HandshakeCrypto(privateKey);
            hd.update(ClientHello);
            hd.update(Session);
            byte[] digest = hd.digest();
            byte[] signedDigest = hc.encrypt(digest);
            String encodedDigest = Base64.getEncoder().encodeToString(signedDigest);
            hm.put("Signature", encodedDigest);

            LocalDateTime ldt = LocalDateTime.now();
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String dateTime = ldt.format(dtf);
            byte[] dtArray = dateTime.getBytes(StandardCharsets.UTF_8);
            byte[] signedDT = hc.encrypt(dtArray);
            String encodedDT = Base64.getEncoder().encodeToString(signedDT);
            hm.put("TimeStamp", encodedDT);
            
            hm.send(socket);
        }
        catch(NoSuchAlgorithmException nsae) {
            System.err.printf("Error creating digest\n");    
            System.exit(1);
        }
        catch(InvalidKeySpecException ikse) {
            System.err.printf("Error instatiating private key\n");
            System.exit(1);
        }
        catch(NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.printf("Error encrypting digest\n");
            System.exit(1);
        }
        catch(IOException ioe) {
            System.err.printf("Error sending ClientFinished\n");
            System.exit(1);
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
        
        sendClientHello(socket, clientCert);
        if(ClientHello == null) {
            System.exit(1);
        }
        HandshakeCertificate serverCert = recvServerHello(socket, caCert);
        if(serverCert == null || ServerHello == null) {
            System.exit(1);
        }
        SessionCipher sessionCipher = sendSession(socket, serverCert);
        if(sessionCipher == null || Session == null) {
            System.exit(1);
        }
        recvServerFinished(socket, serverCert);
        sendClientFinished(socket, key);

        try {
            OutputStream os = sessionCipher.openEncryptedOutputStream(socket.getOutputStream());
            InputStream is = sessionCipher.openDecryptedInputStream(socket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out, is, os, socket);
        }
        catch(IOException ioe) {
            System.err.println("Stream forwarding error\n");
            System.exit(1);
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.err.println("Error opening encrypted and/or decrypted stream");
            System.exit(1);
        }
    }
}