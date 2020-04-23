package com.secstore.sscp;

import static com.secstore.Logger.Loggable;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Key;
import javax.crypto.Cipher;


public abstract class SscpConnection
    implements Loggable
{
    private static final int TRANSFER_BUFFER_SIZE = 8192;
    
    private final Key[] keys = new Key[SscpProtocol.PROTOCOLS.length];
    
    private final Cipher[] ciphers = new Cipher[SscpProtocol.PROTOCOLS.length];
    {
        SscpProtocol[] protocols = SscpProtocol.PROTOCOLS;
        
        for (int i = 0; i < protocols.length; i++)
            ciphers[i] = protocols[i].generateCipher();
    }
    
    private SscpProtocol protocol = SscpProtocol.DEFAULT;
    private Socket socket = null;
    private SscpInputStream in;
    private SscpOutputStream out;
    
    @Override
    public boolean debug()
    {
        return false;
    }
    
    @Override
    public void log(String message)
    {
        message = "[" + getHostAddress()  + "] [" + protocol + "] " + message;
        
        Loggable.super.log(message);
    }
    
    public void connect(Socket socket)
        throws IOException
    {
        this.socket = socket;
        
        in = new SscpInputStream(this);
        
        in.setProtocol(protocol);
        
        out = new SscpOutputStream(this);
        
        out.setProtocol(protocol);
    }
    
    // Establishes the connection using SSAP and populates keys
    public abstract void establishHandshake() throws IOException;
    
    protected Socket getSocket()
        throws IOException
    {
        return socket;
    }
    
    protected String getHostAddress()
    {
        if (socket == null)
            return null;
        
        return socket.getInetAddress().getHostAddress();
    }
    
    public SscpProtocol getProtocol()
    {
        return protocol;
    }
    
    public void setProtocol(SscpProtocol protocol)
    {
        log("Setting SSCP protocol to: " + protocol);
        
        this.protocol = protocol;
        
        in.setProtocol(protocol);
        
        out.setProtocol(protocol);
    }
    
    public Key getKey(SscpProtocol protocol)
    {
        switch (protocol) {
            case SSCP1:
                return keys[0];
            
            case SSCP2:
                return keys[1];
            
            case DEFAULT:
            default:
                throw new IllegalArgumentException("protocol invalid, must be sscp1 or sscp2");
        }
    }
    
    public void setKey(SscpProtocol protocol, Key key)
    {
        switch (protocol) {
            case SSCP1:
                keys[0] = key;
                break;
            
            case SSCP2:
                keys[1] = key;
                break;
            
            case DEFAULT:
            default:
                throw new IllegalArgumentException("protocol invalid, must be sscp1 or sscp2");
        }
    }
    
    public Cipher getCipher(SscpProtocol protocol)
    {
        switch (protocol) {
            case SSCP1:
                return ciphers[0];
            
            case SSCP2:
                return ciphers[1];
            
            case DEFAULT:
            default:
                throw new IllegalArgumentException("protocol invalid");
        }
    }
    
    private void readUntilEOT(OutputStream outputStream)
        throws IOException
    {
        byte[] buffer = new byte[TRANSFER_BUFFER_SIZE];
        
        int bytesRead;
        
        while ((bytesRead = in.read(buffer, 0, TRANSFER_BUFFER_SIZE)) != -1)
            outputStream.write(buffer, 0, bytesRead);
    }
    
    public String readString()
        throws IOException
    {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            readUntilEOT(byteArrayOutputStream);
            
            return byteArrayOutputStream.toString(SscpProtocol.CHARSET);
        }
    }
    
    public void downloadTo(String fileName)
        throws IOException
    {
        try (FileOutputStream fileOutputStream = new FileOutputStream(fileName)) {
            readUntilEOT(fileOutputStream);
        }
    }
    
    public void writeString(String string)
        throws IOException
    {
        out.write(string.getBytes(SscpProtocol.CHARSET));
        
        out.writeEOT();
    }
    
    public void uploadFrom(String fileName)
        throws IOException
    {
        byte[] buffer = new byte[TRANSFER_BUFFER_SIZE];
        
        int bytesRead;
        
        try (FileInputStream dataInputStream = new FileInputStream(fileName)) {
            while ((bytesRead = dataInputStream.read(buffer, 0, TRANSFER_BUFFER_SIZE)) > 0)
                out.write(buffer, 0, bytesRead);
        }
        
        out.writeEOT();
    }
}
