import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CP2 {

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
    private static Cipher cipher;
    private static X509Certificate serverCert;
    private static String capath = "C:\\Users\\Kenny\\Desktop\\Computer System Engineering\\Labs\\Week 11 Lab\\CA.crt";
    private static byte[] hs_bytes = new byte[32];
    private static byte[] hs_en = new byte[128];


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

            //Start Handshake Protocol
            String hs = "Start File Transfer";
            hs_bytes = hs.getBytes();
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            hs_en = cipher.doFinal(hs_bytes);
            //Sending Handshake Message to Client
            toServer.writeInt(hs_en.length);
            toServer.write(hs_en);
            toServer.flush();

            Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher2.init(Cipher.DECRYPT_MODE,publicKey);

            //await Symmetric Key
            System.out.println("Receiving Encrypted Symmetric Key...");
            numBytes = fromServer.readInt();
            filename = new byte[numBytes];
            fromServer.readFully(filename,0,numBytes);

            byte[] symmetricKey_bytes=cipher2.doFinal(filename);
            SecretKey symmetricKey = new SecretKeySpec(symmetricKey_bytes, 0, symmetricKey_bytes.length, "AES");


            //File Transfer
            // Cp1 starts form here

            // Starting File Transger
            // Starting time
            Long startTime = System.currentTimeMillis();
            // cipher and encript with server publickey
            Cipher cipherS = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherS.init(Cipher.ENCRYPT_MODE, symmetricKey);

            String filename1=new String("8.txt");//999
            byte[] filename_encrypted=cipherS.doFinal(filename1.getBytes());

            // Send the filename
            toServer.writeInt(0);
            toServer.writeInt(filename_encrypted.length);
            toServer.write(filename_encrypted);
            toServer.flush();

            FileInputStream fileInputStream = null;
            BufferedInputStream bufferedFileInputStream = null;
            // Open the file
            fileInputStream = new FileInputStream(filename1);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];

            // Send the file // encrypt this
            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer); //num of bytes is 15
                fileEnded = numBytes < 117;

                System.out.println(new String(fromFileBuffer, 0, numBytes));
                //encryption
                byte[] fromFileBuffer_encrypt= cipherS.doFinal(fromFileBuffer);
                //numBytes=fromFileBuffer_encrypt.length;
                //System.out.println("num of bytes:" +fromFileBuffer_encrypt.length); //after encryption is 128
                //System.out.println("num of bytes:" +numBytes);
                numBytes=fromFileBuffer_encrypt.length;

                toServer.writeInt(1);
                toServer.writeInt(numBytes);
                toServer.write(fromFileBuffer_encrypt);
                toServer.flush();
            }

            toServer.writeInt(2);

            System.out.println("File Upload message form server...");
            numBytes = fromServer.readInt();
            filename = new byte[numBytes];
            fromServer.readFully(filename,0,numBytes);
            Long endTime = System.currentTimeMillis();
            Long timeTaken=endTime-startTime;
            System.out.println("Time Taken: "+timeTaken +"ms");

            bufferedFileInputStream.close();
            fileInputStream.close();
        }
        else{
            System.out.println("Bye!");
        }

        System.out.println("Closing connection...");
        toServer.flush();


    }
    public static byte[] generateNonce() throws NoSuchAlgorithmException {
        byte[] nonce=new byte[32];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(nonce);
        return nonce;
    }

}
