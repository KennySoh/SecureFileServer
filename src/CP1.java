import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CP1 {
    //Port Number, HostName, Socket , DataInput, DataOutput, FileInput,BufferedInputStrean
    // Nounce, Message, SignedCertificate, PublicKeyCA,PublicKeySecStore  10.12.54.172
    private static final int portNo=43211;
    // private static final String hostName="localhost";
    private static final String hostName="localhost";//"10.12.54.172";
    private static Socket clientSocket = null;
    private static DataOutputStream toServer = null;
    private static DataInputStream fromServer = null;
    private static final FileInputStream fileInputStream = null;
    private static final BufferedInputStream bufferedFileInputStream = null;
    private static String encryptedNonce;
    private static PublicKey publicKey;
    private static Cipher cipher;
    private static X509Certificate serverCert;
    private static String capath = "C:\\Users\\Li Yang\\IdeaProjects\\ns_assignment\\CA.crt";


    public static void main(String[] args) throws Exception {
        //String filename = "rr.txt";
        //int numBytes = 0;
        System.out.println("Establishing connection to server...");
        // Connect to server and get the input and output streams
        clientSocket = new Socket(hostName, portNo);
        toServer = new DataOutputStream(clientSocket.getOutputStream());
        fromServer = new DataInputStream(clientSocket.getInputStream());

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        //1. Sending First Challenge, Identify yourself!
        System.out.println("Sending Message + Nonce...");
        //String message = "Hello SecStore,please prove your identity!";
        byte[] noncetest = generateNonce();
        System.out.println("Nonce: " + Arrays.toString(noncetest));
        toServer.writeInt(noncetest.length);
        toServer.write(noncetest);
        toServer.flush();

        //2. Getting first response, " encrypted Nonce"
        System.out.println("Receiving Encrypted Nonce Response...");
        int numBytes = fromServer.readInt();
        byte[] filename = new byte[numBytes];
        fromServer.readFully(filename,0,numBytes);
        System.out.println(filename.length);
        encryptedNonce=new String(filename, 0, numBytes);
        System.out.println("Nonce: "+ Arrays.toString(filename));


        //3. Sending SignedCertificate request message
        System.out.println("Sending Signed Certificate Request");
        String messageCert = "Secstore send ur certificate";
        toServer.writeInt(messageCert.getBytes().length);
        toServer.write(messageCert.getBytes());
        toServer.flush();

        //Retrieve Public Key from CA.crt
        InputStream fis = new FileInputStream(capath);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(fis);
        PublicKey caPublicKey = caCert.getPublicKey();
        System.out.println("CA public key extracted");

        //4. Receive Signed Certificate
        //Getting first response, " encrypted Nonce"
        System.out.println("Receiving Signed Certificate Response...");
        int certBytes = fromServer.readInt();
        byte[] cert = new byte[certBytes];
        fromServer.readFully(cert,0,certBytes);
        InputStream in = new ByteArrayInputStream(cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert = (X509Certificate) cf.generateCertificate(in);
        //5. Request PublicKey_CNA from CNA & Decrypt SignedCertificate for PublicKey_SecStore
        System.out.println("5. getting public key, from signed certificate");
        serverCert.checkValidity();
        serverCert.verify(caPublicKey);
        //Once Validated, retrieve the public the key from the serverCert
        publicKey = serverCert.getPublicKey();
        System.out.println("Public Key is" +publicKey.toString());

        //6. Decrypt Message for Nonce
        int start = 0;
        System.out.println("6. decrypting nonce with public key");
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedNonce=cipher.doFinal(filename);
        System.out.println("Decrypted Nonce: " + decryptedNonce.length);

        //7. Compare Nonce with received Nonce to determine handshake.

        if(Arrays.equals(decryptedNonce,noncetest)){
            //handshake
            System.out.println("YES, both Nonce are the same, IP address is authenticated");

        }else
        {
            System.out.println("BYE!");
        }

        //8. Send a Fresh Nonce to check
        byte[] nonce_fresh = generateNonce();
        System.out.println("Nonce: " + Arrays.toString(nonce_fresh));
        toServer.writeInt(nonce_fresh.length);
        toServer.write(nonce_fresh);
        toServer.flush();

        //9. Received the new Encrypted Nonce from server, commencing decryption to check
        int freshnonceBytes = fromServer.readInt();
        byte[] noncebytes = new byte[freshnonceBytes];
        fromServer.readFully(noncebytes,0,freshnonceBytes);
        System.out.println(noncebytes.length);
        encryptedNonce=new String(noncebytes, 0, freshnonceBytes);
        System.out.println("Nonce: "+ Arrays.toString(noncebytes));
        byte[] freshdecryptedNonce=cipher.doFinal(noncebytes);

        if(Arrays.equals(nonce_fresh,freshdecryptedNonce)){
            System.out.println("Check is a success!");
        }
        else{
            System.out.println("Bye!");
        }


    }
    public static byte[] generateNonce() throws NoSuchAlgorithmException {
        byte[] nonce=new byte[32];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(nonce);
        return nonce;
    }

}