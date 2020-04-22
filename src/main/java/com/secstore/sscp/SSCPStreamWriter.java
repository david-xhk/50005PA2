package com.secstore.sscp;

import static com.secstore.Logger.log;
import static com.secstore.sscp.SSCPProtocol.Version;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;


public class SSCPStreamWriter extends Writer
{
    private SSCPConnection connection;
    private final OutputStream outputStream;
    private Version version;
    private boolean open;
    private Key key;
    private Cipher cipher;
    private int ctr = 1;
    
    public SSCPStreamWriter(SSCPConnection connection)
        throws IOException
    {
        this.connection = connection;
        
        this.outputStream = connection.getOutputStream();
        
        open = true;
        
        setVersion(connection.getVersion());
    }
    
    public Version getVersion()
    {
        return version;
    }
    
    public void setVersion(Version version)
    {
        this.version = version;
        
        initializeCipher();
    }
    
    @Override
    public void write(char[] cbuf, int off, int len)
        throws IOException
    {
        ensureOpen();
        
        byte[] bytes = new byte[len];
        
        for (int i = 0; i < len; i++)
            bytes[i] = (byte) cbuf[off + i];
        
        int ptr = 0;
        
        int bytesLeft = bytes.length;
        
        int maxBlockSize = version.getMaxBlockSize();
        
        int blockSize;
        
        byte[] bytesToEncrypt, encryptedBytes;
        
        try (ByteArrayOutputStream frame = new ByteArrayOutputStream()) {
            while (bytesLeft > 0) {
                blockSize = bytesLeft <= maxBlockSize ? bytesLeft : maxBlockSize;
                
                bytesToEncrypt = new byte[blockSize];
                
                System.arraycopy(bytes, ptr, bytesToEncrypt, 0, blockSize);
                
                ptr += blockSize;
                
                bytesLeft -= blockSize;
                
                encryptedBytes = encryptBytes(bytesToEncrypt);
                
                byte[] header = generateHeader(encryptedBytes, false);
                
                logPacket(header, encryptedBytes.length, encryptedBytes);
                
                frame.write(header);
                
                frame.write(encryptedBytes);
            }
            
            frame.writeTo(outputStream);
        }
    }
    
    public void writeEOF()
        throws IOException
    {
        ensureOpen();
        
        byte[] bytes = encryptBytes("\0".getBytes());
        
        byte[] header = generateHeader(bytes, true);
        
        logPacket(header, bytes.length, bytes);
        
        outputStream.write(header);
        
        outputStream.write(bytes);
    }
    
    private final byte[] generateHeader(byte[] bytes, boolean EOF)
        throws IOException
    {
        ensureOpen();
        
        int firstByte = 0;
        
        if (version == Version.SSCP2)
            firstByte += 0x80;
        
        if (EOF)
            firstByte += 0x40;
        
        firstByte += ((bytes.length & 0x3f00) >> 8);
        
        int secondByte = (bytes.length & 0xff);
        
        return new byte[] {(byte) firstByte, (byte) secondByte};
    }
    
    private final void logPacket(byte[] header, int packetSize, byte[] bytes)
    {
        log("[WRITE] Packet " + (ctr++) + " (header={" + (int) header[0] + ", " + (int) header[1] + "}, packetSize=" + packetSize + ", data=" + Base64.getEncoder().encodeToString(bytes));
    }
    
    private final void initializeCipher()
    {
        key = connection.getKey(version);
        
        cipher = connection.getCipher(version);
        
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        
        catch (InvalidKeyException exception) {
            throw new IllegalArgumentException("key invalid");
        }
    }
    
    private final byte[] encryptBytes(byte[] bytes)
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
        outputStream.close();
        
        open = false;
    }
    
    @Override
    public void flush()
        throws IOException
    {
        ensureOpen();
        
        outputStream.flush();
    }
    
    private final void ensureOpen()
        throws IOException
    {
        if (!open)
            throw new IOException("Stream closed");
    }
}
