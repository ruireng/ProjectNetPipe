import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.io.*;

public class NetPipeServer {
    
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

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
        } catch (IllegalArgumentException iae) {
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

    // verify CA certificate
    private static void verifyCACert(HandshakeCertificate CA) {
        try {
            if(!(CA.getCN().equals("ca-np.ik2206.kth.se"))) {
                throw new CertificateException();
            }
            CA.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying server certificate");
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
            System.err.printf("Error verifying server certificate");
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
    private static void recvClientHello(Socket socket, HandshakeCertificate CA) {
        try {
            HandshakeMessage hm = HandshakeMessage.recv(socket);
            if(hm.getType().getCode() != 1) {
                throw new IOException();
            }
            String encodedCert = hm.getParameter("Certificate");
            byte[] decodedCert = Base64.getDecoder().decode(encodedCert);
            HandshakeCertificate clientCert = new HandshakeCertificate(decodedCert);
            clientCert.verify(CA);
        }
        catch(IOException | ClassNotFoundException e) {
            System.err.printf("Error receiving ClientHello from client");

            System.exit(1);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error reading client certificate");

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
        
        ServerSocket serverSocket = initServerSocket(port);
        if(serverSocket == null) {
            System.exit(1);
        }
        Socket clientSocket = acceptSocket(serverSocket, port);
        if(clientSocket == null) {
            System.exit(1);
        }

        // wait for a CLIENTHELLO
        recvClientHello(clientSocket, caCert);
        System.out.println("received ClientHello without problems!");
        // use HandshakeCertificate to verify client's certificate
        // use HandshakeMessage to send SERVERHELLO including certificate
        // wait for SESSION
        // use server's private key to create a digest with HandshakeDigest and send SERVERFINISHED
        // wait for CLIENTFINISHED
        // verify the client's digest integrity
        try {
            Forwarder.forwardStreams(System.in, System.out, clientSocket.getInputStream(), clientSocket.getOutputStream(), clientSocket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}