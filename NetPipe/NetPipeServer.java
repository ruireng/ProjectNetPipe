import java.net.*;
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
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    // main program
    // parse arguments on command line, wait for connection from client,
    // and call switcher to switch data between streams
    public static void main( String[] args) {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));

        String usercertPath = arguments.get("usercert");
        String cacertPath = arguments.get("cacert");
        String privatekeyPath = arguments.get("key");
        
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        // wait for a CLIENTHELLO
        // use HandshakeCertificate to verify client's certificate
        // use HandshakeMessage to send SERVERHELLO including certificate
        // wait for SESSION
        // use server's private key to create a digest with HandshakeDigest and send SERVERFINISHED
        // wait for CLIENTFINISHED
        // verify the client's digest integrity
        try {
            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}