import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SecStoreClient {
    //Port Number, HostName, Socket , DataInput, DataOutput, FileInput,BufferedInputStrean
    // Nounce, Message, SignedCertificate, PublicKeyCA,PublicKeySecStore  10.12.54.172
    private static final int portNo=43211;
   // private static final String hostName="localhost";
    private static final String hostName="10.12.54.172";
    private static Socket clientSocket = null;
    private static DataOutputStream toServer = null;
    private static DataInputStream fromServer = null;
    private static final FileInputStream fileInputStream = null;
    private static final BufferedInputStream bufferedFileInputStream = null;
    private static String encryptedNonce;
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static Cipher cipher;
    private static X509Certificate serverCert;


    public static void main(String[] args) throws Exception {
        //String filename = "rr.txt";
        //int numBytes = 0;
        System.out.println("Establishing connection to server...");
        // Connect to server and get the input and output streams
        clientSocket = new Socket(hostName, portNo);
        toServer = new DataOutputStream(clientSocket.getOutputStream());
        fromServer = new DataInputStream(clientSocket.getInputStream());

            //1. Sending First Challenge, Identify yourself!
            System.out.println("Sending Message + Nonce...");
            String message = "Hello SecStore,please prove your identity!";
            message+=1;//generateNonce().toString();
            toServer.writeInt(message.getBytes().length);
            toServer.write(message.getBytes());
            toServer.flush();

            //2. Getting first response, " encrypted Nounce"
            System.out.println("Receiving Encrypted Nonce Response...");
            int numBytes = fromServer.readInt();
            byte[] filename = new byte[numBytes];
            fromServer.read(filename);
            encryptedNonce=new String(filename, 0, numBytes);
            System.out.println(encryptedNonce);


            //3. Sending SignedCertificate request message
            System.out.println("Sending Signed Certificate Request");
            String messageCert = "Secstore send ur certificate";
            toServer.writeInt(message.getBytes().length);
            toServer.write(message.getBytes());
            toServer.flush();

            //4. Receive Signed Certificate
            //Getting first response, " encrypted Nounce"
            System.out.println("Receiving Signed Certificate Response...");

            ObjectInputStream fromClient;
            fromClient = new ObjectInputStream(clientSocket.getInputStream());
            byte[] cert = (byte[]) fromClient.readObject();
            serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert));



            //5. Request PublicKey_CNA from CNA & Decrypt SignedCertificate for PublicKey_SecStore
            System.out.println("5. getting public key, from signed certificate");
            serverCert.checkValidity();
            //Once Validated, retrieve the public the key from the serverCert
            publicKey = serverCert.getPublicKey();
            System.out.println("Public Key is" +publicKey.toString());

            //6. Decrypt Message for Nounce
            System.out.println("6. decrypting nonce with public key");
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedNonce=cipher.doFinal(encryptedNonce.getBytes());

            //7. Compare Nounce with received Nounce to determine handshake.

            if(encryptedNonce.equals(decryptedNonce.toString())){
                //handshake
                System.out.println("YES, both Nonce are the same, IP address is authenticated");

            }else
            {
                System.out.println("BYE!");
            }

    }
    public static byte[] generateNonce() throws NoSuchAlgorithmException {
        byte[] nonce=new byte[16];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(nonce);
        return nonce;
    }

}
