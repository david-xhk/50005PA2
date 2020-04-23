package com.secstore.ssap;

import static com.secstore.utils.CryptoUtils.base64Decode;
import static com.secstore.utils.CryptoUtils.base64Encode;
import static com.secstore.utils.CryptoUtils.decryptBytes;
import static com.secstore.utils.CryptoUtils.encryptBytes;
import static com.secstore.utils.CryptoUtils.generateCertificate;
import static com.secstore.utils.CryptoUtils.initializeCipher;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


public interface SsapProtocol
{
    public static final String SSTP = "SSTP/1.0";
    public static final String NEWLINE = "\r\n";
    public static final String RESOURCES = "src/main/resources";
    public static final String CA_CERT_FILENAME = "cacse.crt";
    public static final String SECSTORE_CERT_FILENAME = "server-e7b8efa0-846d-11ea-ae9d-89114163ae84.crt";
    public static final String SECSTORE_PRIVATE_KEY_FILENAME = "private_key.der";
    
    public static final X509Certificate CA_CERT = generateCACertificate();
    public static final String SECSTORE_CERT_STRING = generateSecStoreCertificateString();
    public static final PrivateKey SECSTORE_PRIVATE_KEY = generateSecStorePrivateKey();
    
    private static X509Certificate generateCACertificate()
    {
        return generateCertificate(Paths.get(RESOURCES, CA_CERT_FILENAME));
    }
    
    private static String generateSecStoreCertificateString()
    {
        try {
            return Files.readString(Paths.get(RESOURCES, SECSTORE_CERT_FILENAME));
        }
        
        catch (IOException exception) {
            throw new IllegalStateException("failed to read certificate");
        }
    }
    
    private static PrivateKey generateSecStorePrivateKey()
    {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(RESOURCES, SECSTORE_PRIVATE_KEY_FILENAME));
            
            return SscpProtocol.SSCP1.generatePrivateKey(keyBytes);
        }
        
        catch (IOException exception) {
            throw new IllegalStateException("could not read secstore private key");
        }
    }
    
    public static void doOpeningHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        throw new UnsupportedOperationException();
    }
    
    public static void doClosingHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        throw new UnsupportedOperationException();
    }
    
    public static String encryptThenEncode(Cipher cipher, Key key, String string)
    {
        initializeCipher(cipher, Cipher.ENCRYPT_MODE, key);
        
        byte[] decryptedBytes = string.getBytes(SscpProtocol.CHARSET);
        
        byte[] encryptedBytes = encryptBytes(cipher, decryptedBytes);
        
        return base64Encode(encryptedBytes);
    }
    
    public static String decodeThenDecrypt(Cipher cipher, Key key, String string)
    {
        initializeCipher(cipher, Cipher.DECRYPT_MODE, key);
        
        byte[] encryptedBytes = base64Decode(string);
        
        byte[] decryptedBytes = decryptBytes(cipher, encryptedBytes);
        
        return new String(decryptedBytes);
    }
    
    public static String decodeEncryptThenEncode(Cipher cipher, Key key, String string)
    {
        initializeCipher(cipher, Cipher.ENCRYPT_MODE, key);
        
        byte[] decodedBytes = base64Decode(string);
        
        byte[] encryptedBytes = encryptBytes(cipher, decodedBytes);
        
        return base64Encode(encryptedBytes);
    }
    
    public static String decodeDecryptThenEncode(Cipher cipher, Key key, String string)
    {
        initializeCipher(cipher, Cipher.DECRYPT_MODE, key);
        
        byte[] decodedBytes = base64Decode(string);
        
        byte[] decryptedBytes = decryptBytes(cipher, decodedBytes);
        
        return base64Encode(decryptedBytes);
    }
    
    public static class SsapProtocolException extends Exception
    {
        public SsapProtocolException()
        {
            super();
        }
        
        public SsapProtocolException(String message)
        {
            super(message);
        }
    }
}
