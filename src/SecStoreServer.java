import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class SecStoreServer {
    public static void main(String[] args) {

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {welcomeSocket = new ServerSocket(43211);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            String message=",";
            while (!connectionSocket.isClosed()) {
                System.out.println("Receiving file...");
                int numBytes = fromClient.readInt();
                byte[] filename = new byte[numBytes];
                fromClient.read(filename);
                message=new String(filename, 0, numBytes);
                System.out.println(new String(filename, 0, numBytes));

                message="[B@74a14482";// slefGenerated for testing
                toClient.writeInt(message.getBytes().length);
                toClient.write(message.getBytes());
                toClient.flush();

                numBytes = fromClient.readInt();
                filename = new byte[numBytes];
                fromClient.read(filename);
                message=new String(filename, 0, numBytes);
                System.out.println(new String(filename, 0, numBytes));

                message="[B@74a14482";// slefGenerated for testing
                toClient.writeInt(message.getBytes().length);
                toClient.write(message.getBytes());
                toClient.flush();

            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}