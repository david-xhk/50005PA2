package com.secstore.sscp;

import static com.secstore.Logger.log;
import static com.secstore.sscp.SSCPProtocol.Version;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


public abstract class SSCPConnection
{
    private Key[] keys;
    private Cipher[] ciphers = new Cipher[Version.LENGTH];
    private Version version = Version.SSCP1;
    private Socket socket;
    private SSCPStreamReader reader;
    private SSCPStreamWriter writer;
    
    public void connect(Socket socket)
        throws IOException
    {
        this.socket = socket;
        
        keys = establishHandshake();
        
        createCiphers();
        
        reader = new SSCPStreamReader(this);
        
        writer = new SSCPStreamWriter(this);
    }
    
    // Establishes the connection using SSAP and populates keys
    protected abstract Key[] establishHandshake();
    
    private final void createCiphers()
    {
        for (int i = 0; i < Version.LENGTH; i++) {
            Version[] versions = Version.values();
            
            try {
                ciphers[i] = Cipher.getInstance(versions[i].getAlgorithm() + "/" + versions[i].getConfig());
            }
            
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalArgumentException("algorithm invalid");
            }
            
            catch (NoSuchPaddingException exception) {
                throw new IllegalArgumentException("padding invalid");
            }
        }
    }
    
    public String readString()
        throws IOException
    {
        final int bufsize = 1024;
        
        char[] cbuf = new char[bufsize];
        
        StringBuilder builder = new StringBuilder();
        
        int bytesRead;
        
        while ((bytesRead = reader.read(cbuf, 0, bufsize)) != -1)
            builder.append(cbuf, 0, bytesRead);
        
        return builder.toString();
    }
    
    public void writeString(String string)
        throws IOException
    {
        writer.write(string);
        
        writer.writeEOF();
    }
    
    public void readIntoFile(File file)
        throws IOException
    {
        try (FileWriter writer = new FileWriter(file)) {
            reader.transferTo(writer);
        }
        
        log("readIntoFile " + file + " is complete!");
    }
    
    public void writeFromFile(File file)
        throws IOException
    {
        try (FileReader reader = new FileReader(file)) {
            reader.transferTo(writer);
        }
        
        writer.writeEOF();
        
        log("writeFromFile " + file + " is complete!");
    }
    
    Version getVersion()
    {
        return version;
    }
    
    public void setVersion(Version version)
    {
        this.version = version;
        
        writer.setVersion(version);
    }
    
    InputStream getInputStream()
        throws IOException
    {
        return socket.getInputStream();
    }
    
    OutputStream getOutputStream()
        throws IOException
    {
        return socket.getOutputStream();
    }
    
    Key getKey(Version version)
    {
        return keys[version.ordinal()];
    }
    
    Cipher getCipher(Version version)
    {
        return ciphers[version.ordinal()];
    }
}
