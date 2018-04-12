import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerCP1 {

    private static final String psFile_path = "C:\\Users\\Li Yang\\IdeaProjects\\ns_assignment\\privateserver.der";
    private static final String server_certpath = "server.crt";
    private static final int PORT = 43211;
    private static PrivateKey privateKey;
    private static Cipher cipher;
    private static X509Certificate serverCert;
    private static byte[] certificate;

    public static void main(String[] args) throws Exception {
        DataInputStream fromClient = null;
        DataOutputStream toClient = null;
        System.out.println("Starting Server...");
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server Stared!");
        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;


        //Retrieve Private Key from privateserver.der
        Path path = Paths.get(psFile_path);
        byte[] privateKeyBytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey = kf.generatePrivate(privateKeySpec);

        //Initialize encryption
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        try{
            System.out.println("Waiting for client on port " +
                    serverSocket.getLocalPort() + "...");
            Socket server = serverSocket.accept();
            System.out.println("Just connected to " + server.getRemoteSocketAddress());
            //Receive Challenge from Client first before sending out the signed message
            fromClient = new DataInputStream(server.getInputStream());
            toClient = new DataOutputStream(server.getOutputStream());
            String challengeNonce = null;
            String challenge = "Hello SecStore,please prove your identity!";
            while (!server.isClosed()) {
                int numBytes = fromClient.readInt();
                byte[] challengeWithNonce = new byte[numBytes];
                fromClient.read(challengeWithNonce);
                challengeNonce = new String(challengeWithNonce, 0, numBytes);
                System.out.println("Original Length: " + challengeWithNonce.length);
                System.out.println("Challenge Length: " +challenge.length());
                //Retrieve the nonce from challengeWithNonce and send it back to the Client
                String expected_response = challengeNonce.substring(challenge.length());
                System.out.println("Expected Response Length: " + expected_response.length());
                //Prepare signed Message to the Client once correct response is received
                byte[] messageBytes;
                messageBytes = expected_response.getBytes();
                System.out.println("From Client: " + challenge + Arrays.toString(messageBytes));
                cipher.doFinal(messageBytes);

                //Send out the signed message to the Client
                toClient.writeInt(messageBytes.length);
                toClient.write(messageBytes);
                toClient.flush();
                System.out.println("Signed Message has been sent to the Client");

                //Wait for the client to request for the signed certificate
                int nextRequest = fromClient.readInt();
                byte[] certRequest = new byte[nextRequest];
                fromClient.read(certRequest);
                System.out.println("From Client: "+ new String(certRequest, 0, numBytes));

                //Prepare and Send Signed Certificate
                System.out.println("Sending serverCert to the Client...");
                toClient.writeInt(0);
                toClient.writeInt(server_certpath.getBytes().length);
                toClient.write(server_certpath.getBytes());
                toClient.flush();
                // Open the file
                fileInputStream = new FileInputStream(server_certpath);
                bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                byte [] fromFileBuffer = new byte[117];

                // Send the file
                for (boolean fileEnded = false; !fileEnded;) {
                    numBytes = bufferedFileInputStream.read(fromFileBuffer);
                    fileEnded = numBytes < fromFileBuffer.length;

                    toClient.writeInt(1);
                    toClient.writeInt(numBytes);
                    toClient.write(fromFileBuffer);
                    toClient.flush();
                }

                bufferedFileInputStream.close();
                fileInputStream.close();

                toClient.writeInt(2);
                toClient.flush();
                System.out.println("Signed Certificate has been sent to the Client");

                //Handshake Protocol: Receive another Nonce and send it back to the client
                int secondNonceBytes = fromClient.readInt();
                byte[] secondNonce = new byte[secondNonceBytes];
                fromClient.read(secondNonce);
                String secondNonce_string = new String(secondNonce, 0, numBytes);
                System.out.println("From Client: " + secondNonce_string);
                secondNonce = DatatypeConverter.parseBase64Binary(secondNonce_string);

                //Encrypt the Nonce
                byte[] encryptNonce = cipher.doFinal(secondNonce);
                System.out.println("Sending encrypted Nonce to the Client...");
                toClient.writeInt(encryptNonce.length);
                toClient.write(encryptNonce);
                toClient.flush();
                System.out.println("Encrypted Nonce sent to the Client");

                System.out.println("Handshake Protocol done, can now commence file transfer");


            }
            fromClient.close();
            toClient.close();
            serverSocket.close();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    private static X509Certificate getCert(InputStream cert) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert = (X509Certificate) cf.generateCertificate(cert);
        return serverCert;
    }
}