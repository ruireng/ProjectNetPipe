import java.io.*;
import java.util.Base64;

public class FileDigest {
    public static void main(String[] args) {
        String filePath = args[0];

        try {
            InputStream is = new FileInputStream(filePath);
            byte[] buffer = new byte[1];
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // read 1 byte at a time because it worked in IK1203 :)
            while(is.read(buffer) != -1) {
                baos.write(buffer);
            }

            // create a digest from the buffer
            byte[] data = baos.toByteArray();
            HandshakeDigest hd = new HandshakeDigest();
            hd.update(data);
            byte[] digest = hd.digest();

            // encode with base64 and print out
            String decodedDigest = Base64.getEncoder().encodeToString(digest);
            System.out.println(decodedDigest);
            is.close();
            baos.close();
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }
}
