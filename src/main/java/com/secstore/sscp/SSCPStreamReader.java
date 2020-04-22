package com.secstore.sscp;

import static com.secstore.Logger.log;
import static com.secstore.sscp.SSCPProtocol.Version;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;


public class SSCPStreamReader extends Reader
{
    private SSCPConnection connection;
    private final InputStream inputStream;
    private Version version;
    private Key key;
    private Cipher cipher;
    private boolean EOF;
    private byte[] buffer;
    private int ptr;
    private int bytesLeft;
    private boolean open;
    private int ctr = 1;
    
    public SSCPStreamReader(SSCPConnection connection)
        throws IOException
    {
        this.connection = connection;
        
        this.inputStream = connection.getInputStream();
        
        EOF = false;
        
        buffer = new byte[0];
        
        ptr = 0;
        
        bytesLeft = 0;
        
        open = true;
    }
    
    @Override
    public int read(char[] cbuf, int off, int len)
        throws IOException
    {
        ensureOpen();
        
        if (len == 0)
            return 0;
        
        if (atEOF())
            return -1;
        
        // if buffer consumed
        if (bytesLeft == 0) {
            
            consumePacket();
            
            if (atEOF())
                return -1;
        }
        
        // skip buffer
        while (true) {
            if (off >= bytesLeft) {
                off -= bytesLeft;
                
                consumePacket();
                
                if (atEOF())
                    return -1;
            }
            
            else {
                ptr += off;
                
                bytesLeft -= off;
                
                break;
            }
        }
        
        int bytesRead = 0;
        
        int bytesToRead;
        
        while (true) {
            bytesToRead = (len < bytesLeft) ? len : bytesLeft;
            
            for (int i = 0; i < bytesToRead; i++)
                cbuf[bytesRead + i] = (char) buffer[ptr + i];
            
            bytesRead += bytesToRead;
            
            if (len >= bytesLeft) {
                len -= bytesLeft;
                
                consumePacket();
                
                return bytesRead;
            }
            
            else {
                ptr += len;
                
                bytesLeft -= len;
                
                return bytesRead;
            }
        }
    }
    
    private final void consumePacket()
        throws IOException
    {
        int firstByte = inputStream.read();
        
        // version is the first bit of the first byte
        Version version = ((firstByte & 0x80) == 0) ? Version.SSCP1 : Version.SSCP2;
        
        if (this.version != version) {
            this.version = version;
            
            initializeCipher();
        }
        
        // packet size is the last 14 bits of the first two bytes
        int packetSize = (((firstByte & 0x3f) << 8) | inputStream.read());
        
        byte[] bytes = new byte[packetSize];
        
        byte[] temp;
        
        int ptr = 0;
        
        int bytesRead, bytesToRead;
        
        while ((bytesToRead = packetSize - ptr) > 0) {
            temp = new byte[bytesToRead];
            
            bytesRead = inputStream.read(temp, 0, bytesToRead);
            
            for (int i = 0; i < bytesRead; i++, ptr++)
                bytes[ptr] = temp[i];
        }
        
        buffer = decryptBytes(bytes);
        
        bytesLeft = buffer.length;
        
        this.ptr = 0;
        
        // EOF is the second bit of the first byte
        EOF = (((firstByte & 0x40) >> 6) == 1);
        
        logPacket(version, EOF, packetSize, bytes);
    }
    
    private final void logPacket(Version version, boolean EOF, int packetSize, byte[] bytes)
    {
        log("[READ] Packet " + (ctr++) + " (version=" + version + ", EOF=" + EOF + ", packetSize=" + packetSize + ", data=" + Base64.getEncoder().encodeToString(bytes) + ")");
    }
    
    private final void initializeCipher()
    {
        key = connection.getKey(version);
        
        cipher = connection.getCipher(version);
        
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        
        catch (InvalidKeyException exception) {
            throw new IllegalArgumentException("key invalid");
        }
    }
    
    private final byte[] decryptBytes(byte[] bytes)
    {
        try {
            return cipher.doFinal(bytes);
        }
        
        catch (IllegalBlockSizeException exception) {
            throw new IllegalArgumentException("block size invalid");
        }
        
        catch (BadPaddingException exception) {
            throw new IllegalArgumentException("padding invalid");
        }
    }
    
    @Override
    public void close()
        throws IOException
    {
        inputStream.close();
        
        open = false;
    }
    
    @Override
    public boolean ready()
        throws IOException
    {
        if (!open)
            return false;
        
        return !EOF && bytesLeft > 0;
    }
    
    private final void ensureOpen()
        throws IOException
    {
        if (!open)
            throw new IOException("Stream closed");
    }
    
    private final boolean atEOF()
    {
        if (EOF) {
            EOF = false;
            
            return true;
        }
        
        return false;
    }
}
