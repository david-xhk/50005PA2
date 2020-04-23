package com.secstore.ssap;

import static com.secstore.utils.CryptoUtils.generateCertificate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


public class SsapProtocol
{
    public static final String SSTP = "SSTP/1.0";
    public static final String NEWLINE = "\r\n";
    public static final String RESOURCES = "src/main/resources";
    public static final String CA_CERT_FILENAME = "cacse.crt";
    public static final String SECSTORE_CERT_FILENAME = "server-e7b8efa0-846d-11ea-ae9d-89114163ae84.crt";
    public static final String SECSTORE_PRIVATE_KEY_FILENAME = "private_key.der";
    
    public static final X509Certificate CA_CERT;
    public static final String SECSTORE_CERT_STRING;
    public static final PrivateKey SECSTORE_PRIVATE_KEY;
    
    static {
        CA_CERT = generateCertificate(Paths.get(RESOURCES, CA_CERT_FILENAME));
        
        try {
            SECSTORE_CERT_STRING = Files.readString(Paths.get(RESOURCES, SECSTORE_CERT_FILENAME));
        }
        
        catch (IOException exception) {
            throw new IllegalStateException("failed to read certificate");
        }
        
        try {
            SECSTORE_PRIVATE_KEY = SscpProtocol.SSCP1.generatePrivateKey(
                Files.readAllBytes(Paths.get(RESOURCES, SECSTORE_PRIVATE_KEY_FILENAME)));
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
