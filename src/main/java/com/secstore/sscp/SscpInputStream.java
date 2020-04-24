package com.secstore.sscp;

import static com.secstore.Logger.Loggable;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import javax.crypto.Cipher;
import com.secstore.Logger.Loggable;
import com.secstore.utils.CryptoUtils;


public class SscpInputStream extends InputStream
    implements Loggable
{
    private SscpConnection connection;
    private final InputStream inputStream;
    private SscpProtocol protocol;
    private Key key;
    private Cipher cipher;
    private boolean EOT;
    private byte[] buffer;
    private int ptr;
    private int bytesLeft;
    private boolean open;
    private int ctr = 1;
    
    private static int debug_MaxDataLength = 60;
    
    @Override
    public boolean debug()
    {
        return connection.debug();
    }
    
    @Override
    public void log(String message)
    {
        message = "[" + connection.getHostAddress()  + "] [" + protocol + "] [IN] " + message;
        
        Loggable.super.log(message);
    }
    
    public SscpInputStream(SscpConnection connection)
        throws IOException
    {
        this.connection = connection;
        
        this.inputStream = connection.getSocket().getInputStream();
        
        EOT = false;
        
        buffer = new byte[0];
        
        ptr = 0;
        
        bytesLeft = 0;
        
        open = true;
    }
    
    public SscpProtocol getProtocol()
    {
        return protocol;
    }
    
    public void setProtocol(SscpProtocol protocol)
    {
        this.protocol = protocol;
    }
    
    @Override
    public int read()
        throws IOException
    {
        byte[] buffer = new byte[1];
        
        if (read(buffer, 0, 1) == -1)
            return -1;
        
        else
            return buffer[0];
    }
    
    @Override
    public int read(byte[] buffer, int offset, int length)
        throws IOException
    {
        ensureOpen();
        
        if (length == 0)
            return 0;
        
        if (atEOT())
            return -1;
        
        // if buffer consumed
        if (bytesLeft == 0) {
            
            consumePacket();
            
            if (atEOT())
                return -1;
        }
        
        // skip buffer
        while (true) {
            if (offset >= bytesLeft) {
                offset -= bytesLeft;
                
                consumePacket();
                
                if (atEOT())
                    return -1;
            }
            
            else {
                ptr += offset;
                
                bytesLeft -= offset;
                
                break;
            }
        }
        
        int bytesRead = 0;
        
        int bytesToRead = 0;
        
        boolean lastPacket;
        
        while (true) {
            lastPacket = (length < bytesLeft);
            
            bytesToRead = lastPacket ? length : bytesLeft;
            
            for (int i = 0; i < bytesToRead; i++)
                buffer[bytesRead++] = this.buffer[ptr++];
            
            bytesLeft -= bytesToRead;
            
            if (!lastPacket) {
                length -= bytesToRead;
                
                consumePacket();
                
                if (!EOT)
                    continue;
            }
            
            break;
        }
        
        return bytesRead;
    }
    
    private final void consumePacket()
        throws IOException
    {
        int firstByte = inputStream.read();
        
        // version is the first bit of the first byte
        SscpProtocol protocol = ((firstByte & 0x80) == 0) ? SscpProtocol.SSCP1 : SscpProtocol.SSCP2;
        
        if (this.protocol != protocol && this.protocol.isNotDefault())
            setProtocol(protocol);
        
        // EOT is the second bit of the first byte
        EOT = (((firstByte & 0x40) >> 6) == 1);
        
        // packet size is the last 14 bits of the first two bytes
        int packetSize = (((firstByte & 0x3f) << 8) | inputStream.read());
        
        byte[] bytes = new byte[packetSize];
        
        int bytesRead = 0;
        
        while (bytesRead < packetSize)
            bytesRead += inputStream.read(bytes, bytesRead, packetSize - bytesRead);
        
        if (this.protocol.isNotDefault())
            bytes = decryptBytes(bytes);
        
        logPacket(bytes);
        
        buffer = bytes;
        
        bytesLeft = buffer.length;
        
        ptr = 0;
    }
    
    private final void logPacket(byte[] packet)
    {
        if (!debug())
            return;
        
        StringBuilder builder = new StringBuilder();
        
        builder.append("Packet " + (ctr++) + " {");
        
        builder.append("EOT=" + EOT + ", ");
        
        builder.append("packet_size=" + packet.length);
        
        if (packet.length > 0) {
            builder.append(", data=");
            
            String data = CryptoUtils.base64Encode(packet);
            
            if (data.length() > debug_MaxDataLength)
                data = data.substring(0, debug_MaxDataLength - 3) + "...";
            
            builder.append(data);
        }
        builder.append("}");
        
        log(builder.toString());
    }
    
    private final void initializeCipher()
    {
        key = connection.getKey(protocol);
        
        cipher = connection.getCipher(protocol);
        
        CryptoUtils.initializeCipher(cipher, Cipher.DECRYPT_MODE, key);
    }
    
    private final byte[] decryptBytes(byte[] bytes)
    {
        if (bytes.length == 0)
            return bytes;
        
        initializeCipher();
        
        return CryptoUtils.decryptBytes(cipher, bytes);
    }
    
    @Override
    public void close()
        throws IOException
    {
        inputStream.close();
        
        open = false;
    }
    
    @Override
    public int available()
    {
        if (!open)
            return -1;
        
        return bytesLeft;
    }
    
    private final void ensureOpen()
        throws IOException
    {
        if (!open)
            throw new IOException("Stream closed");
    }
    
    private final boolean atEOT()
    {
        if (EOT) {
            EOT = false;
            
            bytesLeft = 0;
            
            ptr = buffer.length;
            
            ctr = 1;
            
            return true;
        }
        
        return false;
    }
}

