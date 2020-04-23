package com.secstore.ssap;

import static com.secstore.Logger.log;
import static com.secstore.utils.CryptoUtils.generateCertificate;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


public class Ssap1_0 extends SsapProtocol
{
    public static final String OPENING_HANDSHAKE;
    public static final String CLOSING_HANDSHAKE;
    
    static {
        StringBuilder builder = new StringBuilder();
        
        builder.append("GET HTTP/1.1" + NEWLINE);
        builder.append("Upgrade: SSTP/1.0" + NEWLINE);
        builder.append("Connection: Upgrade" + NEWLINE + NEWLINE);
        
        OPENING_HANDSHAKE = builder.toString();
        
        builder = new StringBuilder();
        
        builder.append("HTTP/1.1 101 Switching Protocols" + NEWLINE);
        builder.append("Upgrade: SSTP/1.0" + NEWLINE);
        builder.append("Connection: Upgrade" + NEWLINE + NEWLINE);
        builder.append(SECSTORE_CERT_STRING + NEWLINE + NEWLINE);
        
        CLOSING_HANDSHAKE = builder.toString();
    }
    
    public static void doOpeningHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        log("STARTING SSAP/1.0 OPENING HANDSHAKE");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        connection.setProtocol(SscpProtocol.DEFAULT);
        
        log("SENDING SSAP/1.0 OPENING HANDSHAKE");
        
        connection.writeString(OPENING_HANDSHAKE);
        
        String response = connection.readString();
        
        log("GOT SSAP/1.0 CLOSING HANDSHAKE: \n" + response);
        
        String serverCertString = null;
        
        try (Scanner scanner = new Scanner(response)) {
            String data = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            Matcher matcher = Pattern.compile("Upgrade: (.*)").matcher(data);
            
            assert (!matcher.find() || !SSTP.equals(matcher.group(1)));
            
            serverCertString = scanner.useDelimiter(NEWLINE + NEWLINE).next();
        }
        
        if (serverCertString == null)
            throw new SsapProtocolException("certificate not found");
        
        log("GENERATING SECSTORE CERTIFICATE");
        
        X509Certificate serverCert = generateCertificate(serverCertString);
        
        log("VERIFYING SECSTORE CERTIFICATE");
        
        try {
            serverCert.checkValidity();
            
            serverCert.verify(CA_CERT.getPublicKey());
            
            log("SECSTORE CERTIFICATE ACCEPTED");
        }
        
        catch (CertificateException exception) {
            throw new SsapProtocolException("certificate exception: " + exception);
        }
        
        catch (InvalidKeyException
            | NoSuchAlgorithmException
            | NoSuchProviderException
            | SignatureException exception) {
            throw new SsapProtocolException("verification exception: " + exception);
        }
        
        log("SETTING SSAP/1.0 KEY");
        
        connection.setKey(SscpProtocol.SSCP1, serverCert.getPublicKey());
        
        connection.setProtocol(originalProtocol);
        
        log("SSAP/1.0 OPENING HANDSHAKE COMPLETED");
    }
    
    public static void doClosingHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        log("STARTING SSAP/1.0 CLOSING HANDSHAKE");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        connection.setProtocol(SscpProtocol.DEFAULT);
        
        String openingHandshake = connection.readString();
        
        log("GOT SSAP/1.0 OPENING HANDSHAKE: \n" + openingHandshake);
        
        try (Scanner scanner = new Scanner(openingHandshake)) {
            String data = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            Matcher matcher = Pattern.compile("Upgrade: (.*)").matcher(data);
            
            if (!matcher.find() || !SSTP.equals(matcher.group(1)))
                throw new SsapProtocolException("protocol not supported");
        }
        
        log("WRITING SSAP/1.0 CLOSING HANDSHAKE");
        
        connection.writeString(CLOSING_HANDSHAKE);
        
        log("SETTING SSAP/1.0 KEY");
        
        connection.setKey(SscpProtocol.SSCP1, SECSTORE_PRIVATE_KEY);
        
        connection.setProtocol(originalProtocol);
        
        log("SSAP/1.0 CLOSING HANDSHAKE COMPLETED");
    }
}
