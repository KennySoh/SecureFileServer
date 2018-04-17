import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerCP2 {
    private static final String psFile_path = "C:\\Users\\Li Yang\\IdeaProjects\\ns_assignment\\privateServer.der";
    //private static final String psFile_path = "privateServer.der";
    private static final String server_certpath = "C:\\Users\\Li Yang\\IdeaProjects\\ns_assignment\\server.crt";
    private static final int PORT = 43211;
    private static PrivateKey privateKey;
    private static Cipher cipher;
    private static byte[] encryptedNonce = new byte[128];
    private static byte[] encryptNonce = new byte[128];


    public static void main(String[] args) throws Exception {
        DataInputStream fromClient = null;
        DataOutputStream toClient = null;
        System.out.println("Starting Server...");
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server Stared!");
        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        //Retrieve Private Key from privateserver.der
        Path path = Paths.get(psFile_path);
        byte[] privateBytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec privatespec = new PKCS8EncodedKeySpec(privateBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey = kf.generatePrivate(privatespec);



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
            String challenge = "Hello SecStore,please prove your identity!";
            while (!server.isClosed()) {
                int numBytes = fromClient.readInt();
                byte[] challengeWithNonce = new byte[numBytes];
                fromClient.readFully(challengeWithNonce,0, numBytes);
                System.out.println("Original Length: " + challengeWithNonce.length);
                System.out.println("Nonce: " + Arrays.toString(challengeWithNonce));
                System.out.println("Challenge Length: " +challenge.length());
                //Retrieve the nonce from challengeWithNonce and send it back to the Client
                // String expected_response = challengeNonce.substring(challenge.length());
                //System.out.println("Expected Response Length: " + expected_response.length());
                //Prepare signed Message to the Client once correct response is received
                //byte[] messageBytes;
                // messageBytes = expected_response.getBytes();
                //System.out.println("From Client: " + challenge + Arrays.toString(messageBytes));
                encryptedNonce = cipher.doFinal(challengeWithNonce);

                //Send out the signed message to the Client
                toClient.writeInt(encryptedNonce.length);
                toClient.write(encryptedNonce);
                toClient.flush();
                System.out.println("Signed Message has been sent to the Client");



                //Wait for the client to request for the signed certificate
                int nextRequest = fromClient.readInt();
                byte[] certRequest = new byte[nextRequest];
                fromClient.readFully(certRequest,0,nextRequest);
                System.out.println("From Client: "+ new String(certRequest, 0, nextRequest));

                //Prepare and Send Signed Certificate
                System.out.println("Sending serverCert to the Client...");
                // send signed certificate
                File certificateFile = new File(server_certpath);
                byte[] certByteArray = new byte[(int) certificateFile.length()];
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(certificateFile));
                bis.read(certByteArray, 0, certByteArray.length);

                toClient.writeInt(certByteArray.length);
                toClient.write(certByteArray);
                toClient.flush();
                System.out.println("Signed Certificate has been sent to the Client");

                //Handshake Protocol: Receive another Nonce and send it back to the client
                int hsBytes = fromClient.readInt();
                byte[] hs_message = new byte[hsBytes];
                fromClient.readFully(hs_message,0,hsBytes);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decrypted_hs=cipher.doFinal(hs_message);
                String hs_string = new String(decrypted_hs);
                System.out.println("Handshake Message: " + hs_string);
                System.out.println("Handshake Protocol done, can now commence file transfer");


                //create symmetric key
                KeyGenerator keyGen= KeyGenerator.getInstance("AES");
                SecretKey symmetricKey =keyGen.generateKey();

                Cipher cipherSE = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipherSE.init(Cipher.ENCRYPT_MODE, symmetricKey);

                Cipher cipherSD = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipherSD.init(Cipher.DECRYPT_MODE, symmetricKey);

                // create cipher object, initialize to decrypt mode, using Private Key
                Cipher rsaDecryption = Cipher.getInstance("RSA");
                rsaDecryption.init(Cipher.ENCRYPT_MODE, privateKey);

                //Encrypt Symmetric key and send over
                System.out.println("SymmetricKey Send Over");
                byte[] symmetricKey_encrypt=rsaDecryption.doFinal(symmetricKey.getEncoded());
                toClient.writeInt(symmetricKey_encrypt.length);
                toClient.write(symmetricKey_encrypt);
                toClient.flush();

                while(true){
                    int packetType = fromClient.readInt();
                    int encryptedFileBytes = 0;
                    byte[] FileBytes;
                    // If the packet is for transferring the filename
                    if (packetType == 0) {
                        encryptedFileBytes = fromClient.readInt();
                        FileBytes = new byte[encryptedFileBytes];
                        fromClient.readFully(FileBytes,0,encryptedFileBytes);
                        System.out.println(new String(FileBytes, 0, encryptedFileBytes));
                        byte[] decryptedBytes = cipherSD.doFinal(FileBytes);
                        System.out.println(new String(decryptedBytes, 0, decryptedBytes.length));
                        fileOutputStream = new FileOutputStream("C:\\Users\\Li Yang\\IdeaProjects\\ns_assignment\\recv_" + new String(decryptedBytes, 0, decryptedBytes.length));
                        bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                    }
                    // If the packet is for transferring a chunk of the file
                    else if (packetType == 1) {
                        numBytes = fromClient.readInt();
                        System.out.println("num bytes recieved Encrpyted:"+numBytes);
                        if (numBytes > 0) {
                            byte [] block = new byte[numBytes];
                            fromClient.readFully(block, 0, numBytes);
                            System.out.println("encrypted file: "+new String(block, 0, block.length));
                            byte[] decryptedBytes2 = cipherSD.doFinal(block);
                            numBytes=decryptedBytes2.length;
                            System.out.println("num of Bytes decrypted: "+ numBytes);
                            System.out.println(new String(decryptedBytes2, 0, decryptedBytes2.length));
                            bufferedFileOutputStream.write(decryptedBytes2, 0, decryptedBytes2.length);
                        }

                        if (numBytes < 128) {
                            /*
                            System.out.println("File has been uploaded");
                            System.out.println("Closing connection...");

                            String doneMessage="Done";
                            toClient.writeInt(doneMessage.getBytes().length);
                            toClient.write(doneMessage.getBytes());
                            toClient.flush();


                            if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                            if (bufferedFileOutputStream != null) fileOutputStream.close();
                            fromClient.close();
                            toClient.close();
                            serverSocket.close();
                            server.close();
                            */
                        }
                    }
                    else if(packetType==2){
                        System.out.println("File has been uploaded");
                        System.out.println("Closing connection...");

                        String doneMessage="Done";
                        toClient.writeInt(doneMessage.getBytes().length);
                        toClient.write(doneMessage.getBytes());
                        toClient.flush();

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        serverSocket.close();
                        server.close();
                        break;
                    }
                }
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
