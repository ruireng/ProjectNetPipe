import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

import java.io.*;

public class NetPipeServer {
    
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
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
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");

        System.exit(1);
    }

    // parse arguments on command line
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
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
            System.err.printf("Can't find file %s\n", pathName);
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
            String CN = CA.getCN();
            String email = CA.getEmail();
            if(!(CN.equals("ca-np.ik2206.kth.se")) || !(email.contains("@kth.se"))) {
                throw new CertificateException();
            }
            CA.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying server certificate\n");
            System.exit(1);
        }
    }

    // verify client certificate against CA
    private static void verifyClientCert(HandshakeCertificate client, HandshakeCertificate CA) {
        try {
            String CN = client.getCN();
            String email = client.getEmail();
            if(!(CN.equals("client-np.ik2206.kth.se")) || !(email.contains("@kth.se"))) {
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
            String CN = server.getCN();
            String email = server.getEmail();
            if(!(CN.equals("server-np.ik2206.kth.se")) || !(email.contains("@kth.se"))) {
                throw new CertificateException();
            }
            server.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying server certificate\n");
            System.exit(1);
        }
    }

    // initiate server socket
    private static ServerSocket initServerSocket(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);

            return serverSocket;
        }
        catch(IOException ioe) {
            System.err.printf("Error listening on port %d\n", port);            
            return null;
        }
    }

    // accept client socket from server socket
    private static Socket acceptSocket(ServerSocket serverSocket, int port) {
        try {
            Socket socket = serverSocket.accept();

            return socket;
        } catch (IOException ioe) {
            System.err.printf("Error accepting connection on port %d\n", port);            
            return null;
        }
    }

    // receive ClientHello message and verify client certificate
    private static HandshakeCertificate recvClientHello(Socket socket, HandshakeCertificate CA) {
        try {
            HandshakeMessage hm = HandshakeMessage.recv(socket);
            if(hm.getType().getCode() != 1) {
                throw new IOException();
            }
            String encodedCert = hm.getParameter("Certificate");
            byte[] decodedCert = Base64.getDecoder().decode(encodedCert);
            HandshakeCertificate clientCert = new HandshakeCertificate(decodedCert);
            verifyClientCert(clientCert, CA);
            ClientHello = hm.getBytes();

            return clientCert;
        }
        catch(IOException | ClassNotFoundException e) {
            System.err.printf("Error receiving ClientHello from client\n");
            return null;
        }
        catch(CertificateException ce) {
            System.err.printf("Error reading client certificate\n");
            return null;
        }
    }

    // send ServerHello message
    private static void sendServerHello(Socket socket, HandshakeCertificate servercert) {
        HandshakeMessage hm = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        try {
            X509Certificate cert = servercert.getCertificate();
            byte[] certBytes = cert.getEncoded();
            String encodedCert = Base64.getEncoder().encodeToString(certBytes);
            hm.put("Certificate", encodedCert);
            ServerHello = hm.getBytes();

            hm.send(socket);
        }
        catch(CertificateEncodingException cee) {
            System.err.printf("Error getting encoded certificate\n");
            System.exit(1);
        }
        catch(IOException ioe) {
            System.err.printf("Error sending ServerHello\n");
            System.exit(1);
        }
    }

    // receive Session message and get session key + IV
    private static SessionCipher recvSession(Socket socket, byte[] privateKey) {
        try {
            HandshakeMessage hm = HandshakeMessage.recv(socket);
            HandshakeCrypto hc = new HandshakeCrypto(privateKey);
            if(hm.getType().getCode() != 3) {
                throw new IOException();
            }          
            String encodedSK = hm.getParameter("SessionKey");
            String encodedIV = hm.getParameter("SessionIV");
            byte[] decodedSK = Base64.getDecoder().decode(encodedSK);
            byte[] decodedIV = Base64.getDecoder().decode(encodedIV);
            decodedSK = hc.decrypt(decodedSK);
            decodedIV = hc.decrypt(decodedIV);
            SessionKey sk = new SessionKey(decodedSK);
            SessionCipher sc = new SessionCipher(sk, decodedIV);
            Session = hm.getBytes();

            return sc;
        }
        catch(IOException | ClassNotFoundException e) {
            System.err.printf("Error receiving Session from client\n");
            return null;
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.printf("Error instantiating private key\n");
            return null;
        }
        catch(NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.printf("Error using private key\n");
            return null;
        }
    }

    // send ServerFinished message
    private static void sendServerFinished(Socket socket, byte[] privateKey) {
        HandshakeMessage hm = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        try {
            HandshakeDigest hd = new HandshakeDigest();
            HandshakeCrypto hc = new HandshakeCrypto(privateKey);
            hd.update(ServerHello);
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
            System.err.printf("Error sending ServerFinished\n");
            System.exit(1);
        }
    }

    // receive ClientFinished message and check integrity and authentication of handshake
    private static void recvClientFinished(Socket socket, HandshakeCertificate clientCert) {
        HandshakeCrypto hc = new HandshakeCrypto(clientCert);
        try {
            HandshakeMessage hm = HandshakeMessage.recv(socket);
            if(hm.getType().getCode() != 4) {
                throw new IOException();
            }

            LocalDateTime serverLDT = LocalDateTime.now();
            String encodedClientTD = hm.getParameter("TimeStamp");
            byte[] decodedClientTD = Base64.getDecoder().decode(encodedClientTD);
            decodedClientTD = hc.decrypt(decodedClientTD);
            String clientTD = new String(decodedClientTD, StandardCharsets.UTF_8);
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            LocalDateTime clientLDT = LocalDateTime.parse(clientTD, dtf);
            Duration duration = Duration.between(clientLDT, serverLDT);
            long secondsDiff = duration.getSeconds();
            if(Math.abs(secondsDiff) > 10) {
                throw new DateTimeException("");
            }

            HandshakeDigest hd = new HandshakeDigest();
            String encodedSign = hm.getParameter("Signature");
            byte[] decodedSign = Base64.getDecoder().decode(encodedSign);
            byte[] clientDigest = hc.decrypt(decodedSign);
            hd.update(ClientHello);
            hd.update(Session);
            byte[] localDigest = hd.digest();
            if(!(Arrays.equals(localDigest, clientDigest))) {
                throw new ArrayStoreException(); // might be bad programming but I want a unique Exception to catch
            }
        }
        catch(IOException | ClassNotFoundException e) {
            System.err.printf("Error receiving ClientFinished from client\n");
            System.exit(1);
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.printf("Error decrypting ClientFinished from client\n");
            System.exit(1);
        }
        catch(DateTimeException dte) {
            System.err.printf("ClientFinished message too old (10 seconds)\n");
            System.exit(1);
        }
        catch(ArrayStoreException ase) {
            System.err.printf("Integrity check failed\n");
            System.exit(1);
        }
    }

    // main program
    // parse arguments on command line, wait for connection from client,
    // and call switcher to switch data between streams
    public static void main(String[] args) {
        parseArgs(args);
        int port = Integer.parseInt(arguments.get("port"));
        String usercertPath = arguments.get("usercert");
        String cacertPath = arguments.get("cacert");
        String privatekeyPath = arguments.get("key");

        HandshakeCertificate serverCert = initCert(usercertPath);
        HandshakeCertificate caCert = initCert(cacertPath);
        if(serverCert == null || caCert == null) {
            System.exit(1);
        }
        verifyCACert(caCert);
        verifyServerCert(serverCert, caCert);
        byte[] key = initKey(privatekeyPath);
        if(key == null) {
            System.exit(1);
        }
        
        ServerSocket serverSocket = initServerSocket(port);
        if(serverSocket == null) {
            System.exit(1);
        }
        Socket clientSocket = acceptSocket(serverSocket, port);
        if(clientSocket == null) {
            System.exit(1);
        }

        HandshakeCertificate clientCert = recvClientHello(clientSocket, caCert);
        if(clientCert == null || ClientHello == null) {
            System.exit(1);
        }
        sendServerHello(clientSocket, serverCert);
        if(ServerHello == null) {
            System.exit(1);
        }
        SessionCipher sessionCipher = recvSession(clientSocket, key);
        if(sessionCipher == null || Session == null) {
            System.exit(1);
        }
        sendServerFinished(clientSocket, key);
        recvClientFinished(clientSocket, clientCert);

        try {
            OutputStream os = sessionCipher.openEncryptedOutputStream(clientSocket.getOutputStream());
            InputStream is = sessionCipher.openDecryptedInputStream(clientSocket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out, is, os, clientSocket);
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