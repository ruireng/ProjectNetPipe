import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
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
        catch(IllegalArgumentException ex) {
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

    // verify client certificate against CA
    private static void verifyCert(HandshakeCertificate client, HandshakeCertificate CA) {
        try {
            client.verify(CA);
        }
        catch(CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.printf("Error verifying client certificate");
            System.exit(1);
        }
    }

    // initiate socket
    private static Socket initSocket(String host, int port) {
        try {
            Socket socket = new Socket(host, port);

            return socket;
        }
        catch(IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            
            return null;
        }
    }

    // main program
    // parse arguments on command line, connect to server,
    // and call forwarder to forward data between streams
    public static void main( String[] args) {
        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        
        String usercertPath = arguments.get("usercert");
        String cacertPath = arguments.get("cacert");
        String privatekeyPath = arguments.get("key");

        HandshakeCertificate clientCert = initCert(usercertPath);
        HandshakeCertificate CAcert = initCert(cacertPath);
        if(clientCert == null || CAcert == null) {
            System.exit(1);
        }
        verifyCert(clientCert, CAcert);

        Socket socket = initSocket(host, port);
        if(socket == null) {
            System.exit(1);
        }
        
        // use HandshakeMessage to send CLIENTHELLO to server
        // wait for SERVERHELLO
        // use HandshakeCertificate to verify server's certificate
        // send SESSION to server
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