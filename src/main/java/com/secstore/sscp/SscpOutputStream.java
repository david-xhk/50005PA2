package com.secstore.sscp;

import static com.secstore.Logger.log;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import javax.crypto.Cipher;
import com.secstore.utils.CryptoUtils;


public class SscpOutputStream extends OutputStream
{
    private SscpConnection connection;
    private final OutputStream outputStream;
    private byte[] buffer;
    private int ptr;
    private int spacesLeft;
    private boolean initialized;
    private SscpProtocol protocol;
    private boolean open;
    private Key key;
    private Cipher cipher;
    private int ctr = 1;
    
    public SscpOutputStream(SscpConnection connection)
        throws IOException
    {
        this.connection = connection;
        
        this.outputStream = connection.getSocket().getOutputStream();
        
        buffer = new byte[0];
        
        ptr = 0;
        
        spacesLeft = 0;
        
        initialized = false;
        
        open = true;
    }
    
    public SscpProtocol getProtocol()
    {
        return protocol;
    }
    
    public void setProtocol(SscpProtocol protocol)
    {
        if (this.protocol == protocol)
            return;
        
        this.protocol = protocol;
        
        initialized = false;
    }
    
    @Override
    public void write(int value)
        throws IOException
    {
        write(new byte[] { (byte) value }, 0, 1);
    }
    
    @Override
    public void write(byte[] buffer, int offset, int length)
        throws IOException
    {
        ensureOpen();
        
        if (!initialized)
            initialize();
        
        if ((offset + length) > buffer.length)
            throw new IndexOutOfBoundsException();
        
        for (int i = 0; i < length; i++) {
            if (spacesLeft == 0)
                writePacket();
            
            this.buffer[ptr++] = buffer[offset + i];
            
            spacesLeft--;
        }
    }
    
    public void writePacket()
        throws IOException
    {
        if (ptr == 0)
            return;
        
        switch (protocol) {
            case SSCP1:
            case SSCP2:
                byte[] bytesToEncrypt = new byte[ptr];
                
                System.arraycopy(buffer, 0, bytesToEncrypt, 0, ptr);
                
                try (ByteArrayOutputStream frame = new ByteArrayOutputStream()) {
                    byte[] encryptedBytes = encryptBytes(bytesToEncrypt);
                    
                    byte[] header = generateHeader(encryptedBytes, false);
                    
                    logPacket(header, encryptedBytes.length, encryptedBytes);
                    
                    frame.write(header);
                        
                    frame.write(encryptedBytes);
                    
                    frame.writeTo(outputStream);
                }
                
                break;
            
            case DEFAULT:
            default:
                outputStream.write(0);
                
                outputStream.write(new byte[] {
                    (byte) (ptr >> 24),
                    (byte) (ptr >> 16),
                    (byte) (ptr >> 8),
                    (byte) (ptr)
                });
                
                outputStream.write(buffer, 0, ptr);
                
                break;
        }
        
        spacesLeft += ptr;
        
        ptr = 0;
        
        initializeBuffer();
    }
    
    public void writeEOT()
        throws IOException
    {
        ensureOpen();
        
        flush();
        
        switch (protocol) {
            case SSCP1:
            case SSCP2:
                byte[] bytes = encryptBytes(SscpProtocol.EOT_MESSAGE);
                
                byte[] header = generateHeader(bytes, true);
                
                logPacket(header, bytes.length, bytes);
                
                outputStream.write(header);
                
                outputStream.write(bytes);
                
                break;
            
            case DEFAULT:
            default:
                outputStream.write(SscpProtocol.EOT_BYTE);
                
                break;
        }
        
        outputStream.flush();
        
        ctr = 1;
    }
    
    private final byte[] generateHeader(byte[] bytes, boolean EOT)
        throws IOException
    {
        ensureOpen();
        
        int firstByte = 0;
        
        if (protocol == SscpProtocol.SSCP2)
            firstByte += 0x80;
        
        if (EOT)
            firstByte += 0x40;
        
        firstByte += ((bytes.length & 0x3f00) >> 8);
        
        int secondByte = (bytes.length & 0xff);
        
        return new byte[] {(byte) firstByte, (byte) secondByte};
    }
    
    private final void logPacket(byte[] header, int packetSize, byte[] bytes)
    {
        log("[WRITE] Packet " + (ctr++) + " (header={" + (int) header[0] + ", " + (int) header[1] +
            "}, packetSize=" + packetSize + ", data=" + CryptoUtils.base64Encode(bytes) + ")");
    }
    
    private final void initialize()
    {
        switch (protocol) {
            case SSCP1:
            case SSCP2:
                initializeCipher();
            
            case DEFAULT:
            default:
                initializeBuffer();
                
                initialized = true;
        }
    }
    
    private final void initializeBuffer()
    {
        byte[] newBuffer = new byte[protocol.getMaxBlockSize()];
        
        if (ptr > 0)
            System.arraycopy(buffer, 0, newBuffer, 0, ptr);
            
        buffer = newBuffer;
        
        spacesLeft = buffer.length - ptr;
        
    }
    
    private final void initializeCipher()
    {
        key = connection.getKey(protocol);
        
        cipher = connection.getCipher(protocol);
        
        CryptoUtils.initializeCipher(cipher, Cipher.ENCRYPT_MODE, key);
    }
    
    private final byte[] encryptBytes(byte[] bytes)
    {
        if (!initialized)
            initialize();
        
        return CryptoUtils.encryptBytes(cipher, bytes);
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
        
        writePacket();
        
        outputStream.flush();
    }
    
    private final void ensureOpen()
        throws IOException
    {
        if (!open)
            throw new IOException("Stream closed");
    }
}
