package com.secstore.ssap;

import static com.secstore.Logger.log;
import static com.secstore.utils.CryptoUtils.encryptBytes;
import static com.secstore.utils.CryptoUtils.decryptBytes;
import static com.secstore.utils.CryptoUtils.base64Encode;
import static com.secstore.utils.CryptoUtils.base64Decode;
import static com.secstore.utils.CryptoUtils.initializeCipher;
import java.io.IOException;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


public class Ssap2_0 extends SsapProtocol
{
    public static final String UPGRADE = "UPGRADE";
    public static final String HEADER = "SecStore-Session-Key";
    public static final String CLOSING_HANDSHAKE = ""
        + SSTP + " " + 100 + " " + "Secure Connection Initialized" + NEWLINE + NEWLINE;
    
    public static void doOpeningHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        log("STARTING SSAP/2.0 OPENING HANDSHAKE");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        connection.setProtocol(SscpProtocol.SSCP1);
        
        log("GENERATING SESSION KEY");
        
        SecretKey sessionKey = SscpProtocol.SSCP2.generateSecretKey();
        
        byte[] sessionKeyBytes = sessionKey.getEncoded();
        
        String sessionKeyString = base64Encode(sessionKeyBytes);
        
        log("GENERATED SESSION KEY: " + sessionKeyString);
        
        String openingHandshake = (
            UPGRADE + " " + SSTP + NEWLINE +
            HEADER + ": " + sessionKeyString + NEWLINE + NEWLINE);
        
        log("SENDING SSAP/2.0 OPENING HANDSHAKE");
        
        connection.writeString(openingHandshake);
        
        String response = connection.readString();
        
        log("GOT SSAP/2.0 CLOSING HANDSHAKE: \n" + response);
        
        log("DECRYPTING MESSAGE");
        
        Cipher cipher = connection.getCipher(SscpProtocol.SSCP2);
        
        initializeCipher(cipher, Cipher.DECRYPT_MODE, sessionKey);
        
        String decryptedResponse = new String(decryptBytes(cipher, base64Decode(response)));
        
        log("DECRYPTED MESSAGE: \n" + decryptedResponse);
        
        try (Scanner scanner = new Scanner(decryptedResponse)) {
            if (!SSTP.equals(scanner.useDelimiter(" ").next()))
                throw new IllegalStateException("unexpected protocol");
            
            if (scanner.nextInt() != 100)
                throw new SsapProtocolException("sscp2 opening handshake failed: " +
                    scanner.useDelimiter(NEWLINE + NEWLINE).next());
            
            log("CLOSING HANDSHAKE ACCEPTED");
        }
        
        log("SETTING SSAP/2.0 KEY");
        
        connection.setKey(SscpProtocol.SSCP2, sessionKey);
        
        connection.setProtocol(originalProtocol);
        
        log("SSAP/2.0 OPENING HANDSHAKE COMPLETED");
    }
    
    public static void doClosingHandShake(SscpConnection connection)
        throws IOException, SsapProtocolException
    {
        log("STARTING SSAP/2.0 CLOSING HANDSHAKE");
        
        SscpProtocol originalProtocol = connection.getProtocol();
        
        connection.setProtocol(SscpProtocol.SSCP1);
        
        String openingHandshake = connection.readString();
        
        log("GOT SSAP/2.0 OPENING HANDSHAKE: \n" + openingHandshake);
        
        String sessionKeyString = null;
        
        try (Scanner scanner = new Scanner(openingHandshake)) {
            if (!UPGRADE.equals(scanner.useDelimiter(" ").next()))
                throw new IllegalStateException("unexpected request");
            
            if (!SSTP.equals(scanner.useDelimiter(NEWLINE).next().stripLeading()))
                throw new IllegalStateException("unexpected protocol");
            
            String data = scanner.useDelimiter(NEWLINE + NEWLINE).next();
            
            Matcher matcher = Pattern.compile(HEADER + ": (.*)").matcher(data);
            
            if (matcher.find())
                sessionKeyString = matcher.group(1);
        }
        
        if (sessionKeyString == null)
            throw new SsapProtocolException("session key missing");
        
        log("GOT SESSION KEY: " + sessionKeyString);
        
        SecretKey key = SscpProtocol.SSCP2.generateSecretKey(base64Decode(sessionKeyString));
        
        log("ENCRYPTING CLOSING HANDSHAKE");
        
        Cipher cipher = connection.getCipher(SscpProtocol.SSCP2);
        
        initializeCipher(cipher, Cipher.ENCRYPT_MODE, key);
        
        String encryptedHandshake = base64Encode(encryptBytes(cipher, CLOSING_HANDSHAKE.getBytes()));
        
        log("WRITING SSAP/2.0 CLOSING HANDSHAKE");
        
        connection.writeString(encryptedHandshake);
        
        log("SETTING SSAP/2.0 KEY");
        
        connection.setKey(SscpProtocol.SSCP2, key);
        
        connection.setProtocol(originalProtocol);
        
        log("SSAP/2.0 CLOSING HANDSHAKE COMPLETED");
    }
}
