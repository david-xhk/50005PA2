package com.secstore.ssap;

import static com.secstore.utils.CryptoUtils.generateCertificate;
import static com.secstore.utils.CryptoUtils.base64Encode;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


public interface Ssap1_0 extends SsapProtocol
{
    public static SscpProtocol REQUIRED_PROTOCOL = SscpProtocol.DEFAULT;
    public static int NONCE_LENGTH = 64;
    
    public static String generateNonce()
    {
        byte[] nonce = new byte[NONCE_LENGTH];
        
        ThreadLocalRandom.current().nextBytes(nonce);
        
        return base64Encode(nonce);
    }
    
    public static String newOpeningHandshake(String nonce)
    {
        StringBuilder builder = new StringBuilder();
        
        builder.append("GET HTTP/1.1" + NEWLINE);
        builder.append("Upgrade: SSTP/1.0" + NEWLINE);
        builder.append("Connection: Upgrade" + NEWLINE);
        builder.append("Nonce: " + nonce + NEWLINE + NEWLINE);
        
        return builder.toString();
    }
    
    public static String newClosingHandshake(String encryptedNonce)
    {
        StringBuilder builder = new StringBuilder();
        
        builder.append("HTTP/1.1 101 Switching Protocols" + NEWLINE);
        builder.append("Upgrade: SSTP/1.0" + NEWLINE);
        builder.append("Connection: Upgrade" + NEWLINE);
        builder.append("Encrypted-Nonce: " + encryptedNonce + NEWLINE + NEWLINE);
        builder.append(SECSTORE_CERT_STRING + NEWLINE + NEWLINE);
        
        return builder.toString();
    }
    
    public static void doOpeningHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        connection.log("[SSAP/1.0] Starting Opening Handshake");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        if (originalProtocol != null && originalProtocol == REQUIRED_PROTOCOL)
            originalProtocol = null;
        
        else {
            connection.log("[SSAP/1.0] [OPENING] Changing connection protocol");
            
            connection.setProtocol(REQUIRED_PROTOCOL);
        }
        
        String nonce = generateNonce();
        
        connection.log("[SSAP/1.0] [OPENING] Generated nonce: " + nonce);
        
        String openingHandshake = newOpeningHandshake(nonce);
        
        connection.log("[SSAP/1.0] [OPENING] Sending opening handshake");
        
        connection.writeString(openingHandshake);
        
        connection.log("[SSAP/1.0] [OPENING] Waiting for closing handshake");
        
        String response = connection.readString();
        
        connection.log("[SSAP/1.0] [OPENING] Got closing handshake: \n" + response);
        
        String encryptedNonce;
        
        String secStoreCertString;
        
        connection.log ("[SSAP/1.0] [OPENING] Parsing closing handshake");
        
        try (Scanner scanner = new Scanner(response)) {
            String data = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            connection.log("[SSAP/1.0] [OPENING] Checking upgrade protocol");
            
            Matcher matcher = Pattern.compile("Upgrade: (.*)").matcher(data);
            
            if (!matcher.find())
                throw new SsapProtocolException("upgrade protocol missing");
            
            else if (!SSTP.equals(matcher.group(1)))
                throw new SsapProtocolException("invalid upgrade protocol");
            
            connection.log("[SSAP/1.0] [OPENING] Getting encrypted nonce");
            
            matcher = Pattern.compile("Encrypted-Nonce: (.*)").matcher(data);
            
            if (matcher.find())
                encryptedNonce = matcher.group(1);
            
            else
                throw new SsapProtocolException("encrypted nonce not found");
            
            connection.log("[SSAP/1.0] [OPENING] Got encrypted nonce: " + encryptedNonce);
            
            connection.log("[SSAP/1.0] [OPENING] Getting SecStore certificate");
            
            secStoreCertString = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            if (secStoreCertString == null)
                throw new SsapProtocolException("certificate not found");
        }
        
        connection.log("[SSAP/1.0] [OPENING] Generating SecStore certificate");
        
        X509Certificate secStoreCert = generateCertificate(secStoreCertString);
        
        connection.log("[SSAP/1.0] [OPENING] Verifying SecStore certificate");
        
        try {
            secStoreCert.checkValidity();
            
            secStoreCert.verify(CA_CERT.getPublicKey());
            
            connection.log("[SSAP/1.0] [OPENING] SecStore certificate verified");
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
        
        connection.log("[SSAP/1.0] [OPENING] Decrypting encrypted nonce");
        
        PublicKey key = secStoreCert.getPublicKey();
        
        Cipher cipher = connection.getCipher(SscpProtocol.SSCP1);
        
        String decryptedNonce = SsapProtocol.decodeDecryptThenEncode(cipher, key, encryptedNonce);
        
        connection.log("[SSAP/1.0] [OPENING] Got decrypted nonce: " + decryptedNonce);
        
        if (!decryptedNonce.equals(nonce))
            throw new SsapProtocolException("encrypted nonce invalid");
        
        connection.log("[SSAP/1.0] [OPENING] Nonce accepted");
        
        connection.log("[SSAP/1.0] [OPENING] Setting keys");
        
        connection.setKey(SscpProtocol.SSCP1, key);
        
        if (originalProtocol != null) {
            connection.log("[SSAP/1.0] [OPENING] Restoring original protocol");
            
            connection.setProtocol(originalProtocol);
        }
        
        connection.log("[SSAP/1.0] [OPENING] Handshake Complete");
    }
    
    public static void doClosingHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        connection.log("[SSAP/1.0] Starting Closing Handshake");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        if (originalProtocol != null && originalProtocol == REQUIRED_PROTOCOL)
            originalProtocol = null;
        
        else {
            connection.log("[SSAP/1.0] [CLOSING] Changing connection protocol");
            
            connection.setProtocol(REQUIRED_PROTOCOL);
        }
        
        connection.log("[SSAP/1.0] [CLOSING] Waiting for opening handshake");
        
        String openingHandshake = connection.readString();
        
        connection.log("[SSAP/1.0] [CLOSING] Got opening handshake: \n" + openingHandshake);
        
        String nonce;
        
        connection.log("[SSAP/1.0] [CLOSING] Parsing opening handshake");
        
        try (Scanner scanner = new Scanner(openingHandshake)) {
            String data = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            connection.log("[SSAP/1.0] [CLOSING] Checking upgrade protocol");
            
            Matcher matcher = Pattern.compile("Upgrade: (.*)").matcher(data);
            
            if (!matcher.find() || !SSTP.equals(matcher.group(1)))
                throw new SsapProtocolException("protocol not supported");
            
            connection.log("[SSAP/1.0] [CLOSING] Getting nonce");
            
            matcher = Pattern.compile("Nonce: (.*)").matcher(data);
            
            if (matcher.find())
                nonce = matcher.group(1);
            
            else
                throw new SsapProtocolException("encrypted nonce not found");
            
            connection.log("[SSAP/1.0] [CLOSING] Got nonce: " + nonce);
        }
        
        connection.log("[SSAP/1.0] [CLOSING] Encrypting nonce");
        
        PrivateKey key = SECSTORE_PRIVATE_KEY;
        
        Cipher cipher = connection.getCipher(SscpProtocol.SSCP1);
        
        String encryptedNonce = SsapProtocol.decodeEncryptThenEncode(cipher, key, nonce);
        
        connection.log("[SSAP/1.0] [CLOSING] Got encrypted nonce: " + encryptedNonce);
        
        connection.log("[SSAP/1.0] [CLOSING] Sending closing handshake");
        
        String closingHandshake = newClosingHandshake(encryptedNonce);
        
        connection.writeString(closingHandshake);
        
        connection.log("[SSAP/1.0] [CLOSING] Setting keys");
        
        connection.setKey(SscpProtocol.SSCP1, key);
        
        if (originalProtocol != null) {
            connection.log("[SSAP/1.0] [CLOSING] Restoring original protocol");
            
            connection.setProtocol(originalProtocol);
        }
        
        connection.log("[SSAP/1.0] [CLOSING] Handshake Complete");
    }
}
