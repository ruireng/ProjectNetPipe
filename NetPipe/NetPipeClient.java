import java.net.*;
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
        System.exit(1);
    }

    // parse arguments on command line
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");

        arguments.setArgumentSpec("usercert", "client certificate");
        arguments.setArgumentSpec("cacert", "CA certificate");
        arguments.setArgumentSpec("key", "client private key");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    // main program
    // parse arguments on command line, connect to server,
    // and call forwarder to forward data between streams
    public static void main( String[] args) {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        
        String usercertPath = arguments.get("usercert");
        String cacertPath = arguments.get("cacert");
        String privatekeyPath = arguments.get("key");

        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
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