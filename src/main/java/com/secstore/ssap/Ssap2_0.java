package com.secstore.ssap;

import static com.secstore.utils.CryptoUtils.base64Encode;
import static com.secstore.utils.CryptoUtils.base64Decode;
import java.io.IOException;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


public interface Ssap2_0 extends SsapProtocol
{
    public static final SscpProtocol REQUIRED_PROTOCOL = SscpProtocol.SSCP1;
    public static final String REQUEST = "UPGRADE";
    public static final int RESPONSE_CODE = 100;
    public static final String SESSION_KEY_HEADER = "SecStore-Session-Key";
    public static final String CLOSING_HANDSHAKE = newClosingHandshake();
    
    public static String newOpeningHandshake(String sessionKeyString)
    {
        StringBuilder builder = new StringBuilder();
        
        builder.append(REQUEST + " " + SSTP + NEWLINE);
        builder.append(SESSION_KEY_HEADER + ": " + sessionKeyString + NEWLINE + NEWLINE);
        
        return builder.toString();
    }
    
    private static String newClosingHandshake()
    {
        return SSTP + " " + RESPONSE_CODE + " " + "Secure Connection Initialized" + NEWLINE + NEWLINE;
    }
    
    public static void doOpeningHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        connection.log("[SSAP/2.0] Starting Opening Handshake");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        if (originalProtocol != null && originalProtocol == REQUIRED_PROTOCOL)
            originalProtocol = null;
        
        else {
            connection.log("[SSAP/2.0] [OPENING] Changing connection protocol");
            
            connection.setProtocol(REQUIRED_PROTOCOL);
        }
        
        connection.log("[SSAP/2.0] [OPENING] Generating session key");
        
        SecretKey sessionKey = SscpProtocol.SSCP2.generateSecretKey();
        
        String sessionKeyString = base64Encode(sessionKey.getEncoded());
        
        connection.log("[SSAP/2.0] [OPENING] Generated session key: " + sessionKeyString);
        
        String openingHandshake = newOpeningHandshake(sessionKeyString);
        
        connection.log("[SSAP/2.0] [OPENING] Sending opening handshake");
        
        connection.writeString(openingHandshake);
        
        connection.log("[SSAP/2.0] [OPENING] Waiting for closing handshake");
        
        String response = connection.readString();
        
        connection.log("[SSAP/2.0] [OPENING] Got closing handshake: \n" + response);
        
        connection.log("[SSAP/2.0] [OPENING] Decrypting closing handshake");
        
        Cipher cipher = connection.getCipher(SscpProtocol.SSCP2);
        
        String decryptedResponse = SsapProtocol.decodeThenDecrypt(cipher, sessionKey, response);
        
        connection.log("[SSAP/2.0] [OPENING] Got decrypted closing handshake: \n" + decryptedResponse);
        
        connection.log("[SSAP/2.0] [OPENING] Parsing decrypted closing handshake");
        
        try (Scanner scanner = new Scanner(decryptedResponse)) {
            connection.log("[SSAP/2.0] [OPENING] Checking protocol");
            
            if (!SSTP.equals(scanner.useDelimiter(" ").next()))
                throw new IllegalStateException("unexpected protocol");
            
            connection.log("[SSAP/2.0] [OPENING] Checking response status");
            
            if (scanner.nextInt() != 100)
                throw new SsapProtocolException("sscp2 opening handshake failed: " +
                    scanner.useDelimiter(NEWLINE + NEWLINE).next());
            
            connection.log("[SSAP/2.0] [OPENING] Closing handshake accepted");
        }
        
        connection.log("[SSAP/2.0] [OPENING] Setting keys");
        
        connection.setKey(SscpProtocol.SSCP2, sessionKey);
        
        if (originalProtocol != null) {
            connection.log("[SSAP/2.0] [OPENING] Restoring original protocol");
            
            connection.setProtocol(originalProtocol);
        }
        
        connection.log("[SSAP/2.0] [OPENING] Handshake Completed");
    }
    
    public static void doClosingHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        connection.log("[SSAP/2.0] Starting Closing Handshake");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        if (originalProtocol != null && originalProtocol == REQUIRED_PROTOCOL)
            originalProtocol = null;
        
        else {
            connection.log("[SSAP/2.0] [CLOSING] Changing connection protocol");
            
            connection.setProtocol(REQUIRED_PROTOCOL);
        }
        
        connection.log("[SSAP/2.0] [CLOSING] Waiting for opening handshake");
        
        String openingHandshake = connection.readString();
        
        connection.log("[SSAP/2.0] [CLOSING] Got opening handshake: \n" + openingHandshake);
        
        String sessionKeyString = null;
        
        connection.log("[SSAP/2.0] [CLOSING] Parsing opening handshake");
        
        try (Scanner scanner = new Scanner(openingHandshake)) {
            connection.log("[SSAP/2.0] [CLOSING] Checking request");
            
            if (!REQUEST.equals(scanner.useDelimiter(" ").next()))
                throw new IllegalStateException("unexpected request");
            
            connection.log("[SSAP/2.0] [CLOSING] Checking protocol");
            
            if (!SSTP.equals(scanner.useDelimiter(NEWLINE).next().stripLeading()))
                throw new IllegalStateException("unexpected protocol");
            
            connection.log("[SSAP/2.0] [CLOSING] Getting session key");
            
            String data = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            Matcher matcher = Pattern.compile("SecStore-Session-Key: (.*)").matcher(data);
            
            if (matcher.find())
                sessionKeyString = matcher.group(1);
            
            else
                throw new SsapProtocolException("session key missing");
        }
        
        connection.log("[SSAP/2.0] [CLOSING] Got session key: " + sessionKeyString);
        
        SecretKey key = SscpProtocol.SSCP2.generateSecretKey(base64Decode(sessionKeyString));
        
        connection.log("[SSAP/2.0] [CLOSING] Encrypting closing handshake");
        
        Cipher cipher = connection.getCipher(SscpProtocol.SSCP2);
        
        String encryptedHandshake = SsapProtocol.encryptThenEncode(cipher, key, CLOSING_HANDSHAKE);
        
        connection.log("[SSAP/2.0] [CLOSING] Sending encrypted closing handshake");
        
        connection.writeString(encryptedHandshake);
        
        connection.log("[SSAP/2.0] [CLOSING] Setting keys");
        
        connection.setKey(SscpProtocol.SSCP2, key);
        
        if (originalProtocol != null) {
            connection.log("[SSAP/2.0] [CLOSING] Restoring original protocol");
            
            connection.setProtocol(originalProtocol);
        }
        
        connection.log("[SSAP/2.0] [CLOSING] Handshake Complete");
    }
}
