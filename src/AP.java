import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * Created by Li Yang on 27/3/2018.
 */

public class AP {
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static Cipher cipher;
    private static byte[] certificate;
    private static X509Certificate serverCert;
    private static byte[] challenge = new byte[16];
    private static byte[] response = new byte[128];

    /*
    For the Server Side, passing over the signed certificate as well as the encyrpted message
    using the private key to the Client
     */
    public AP(InputStream cert, InputStream pK) throws Exception {
        serverCert = getCertificate(cert);
        certificate = serverCert.getEncoded();
        byte [] pkEncoded = new byte[pK.available()];
        pK.read(pkEncoded);
        PKCS8EncodedKeySpec kSpec = new PKCS8EncodedKeySpec(pkEncoded);

        //Generate a private Key
        KeyFactory kf  = KeyFactory.getInstance("RSA");
        privateKey = kf.generatePrivate(kSpec);

        //Encrypt Message using the private key
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    }
    /*
    From the Client Side, issues a challenge to the Server for authentication, also
    once received the serverCert, get the public key and decrypt the message
    given by the Server.
     */

    public AP(InputStream cert) throws Exception {
        //Issues challenge by giving a cryptographically strong random number
        SecureRandom random = new SecureRandom();
        random.nextBytes(challenge);

        serverCert = getCertificate(cert);
        //When received the serverCert, checks the validity of the cert
        serverCert.checkValidity();
        //Once Validated, retrieve the public the key from the serverCert
        publicKey = serverCert.getPublicKey();

        //Decrypt Message using the public Key
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
    }


    public boolean checkResults(InputStream in) {
        try {
            in.read(response);
            return Arrays.equals(challenge, cipher.doFinal(response));
        } catch (Exception e) {
            return false;
        }
    }

    private static X509Certificate getCertificate(InputStream certificate) throws Exception{
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert = (X509Certificate) cf.generateCertificate(certificate);
        return serverCert;
    }

}
