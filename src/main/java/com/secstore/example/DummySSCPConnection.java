package com.secstore.example;

import static com.secstore.Logger.log;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import com.secstore.sscp.SSCPConnection;
import com.secstore.sscp.SSCPProtocol.Version;


public class DummySSCPConnection extends SSCPConnection
{
    private static final String FILE_NAME = "1000.txt";
    private static final String FILE_LOCATION = "src/main/resources";
    private static final String RESULT_LOCATION = "src/main/results";
    
    public static final PublicKey serverPublicKey;
    public static final PrivateKey serverPrivateKey;
    public static final SecretKey symmetricKey;
    
    static {
        KeyPair keyPair = Version.SSCP1.generateKeyPair();
        
        serverPublicKey = keyPair.getPublic();
        serverPrivateKey = keyPair.getPrivate();
        symmetricKey = Version.SSCP2.generateSecretKey();
    }
    
    private Type type;
    
    public static void main(String[] args)
        throws IOException
    {
        String host = "localhost";
        int port = 50000;
        
        SSCPConnection server = new DummySSCPConnection(host, port, Type.SERVER);
        SSCPConnection client = new DummySSCPConnection(host, port, Type.CLIENT);
        
        File readFile = new File(FILE_LOCATION, FILE_NAME);
        log("Server writing file: " + readFile);
        server.setVersion(Version.SSCP2);
        server.writeFromFile(readFile);
        
        File writeFile = new File(RESULT_LOCATION, FILE_NAME);
        log("Client reading into file: " + writeFile);
        client.setVersion(Version.SSCP2);
        client.readIntoFile(writeFile);
    }
    
    public DummySSCPConnection(String host, int port, Type type)
        throws IOException
    {
        this.type = type;
        
        switch (type) {
            case CLIENT:
                log("Client connecting");
                connect(new Socket(host, port));
                
                log("Client connected");
                break;
            
            case SERVER:
                log("Starting server");
                ServerSocket server = new ServerSocket();
                
                server.bind(new InetSocketAddress(host, port));
                log("Server bound to " + server.getInetAddress());
                
                new Thread(() -> {
                    try {
                        log("waiting to connect");
                        Socket socket = server.accept();
                        
                        log("Connected to: " + socket);
                        connect(socket);
                    }
                    
                    catch (IOException exception) {
                        exception.printStackTrace();
                    }
                    
                    finally {
                        try {
                            server.close();
                        }
                        
                        catch (IOException exception) {
                            exception.printStackTrace();
                        }
                    }
                }).start();
                break;
        }
    }
    
    @Override
    protected Key[] establishHandshake()
    {
        switch (type) {
            case SERVER:
                return new Key[] {serverPrivateKey, symmetricKey};
            
            case CLIENT:
                return new Key[] {serverPublicKey, symmetricKey};
            
            default:
                throw new IllegalStateException("unknown type");
        }
    }
    
    public static enum Type
    {
        CLIENT,
        SERVER
    }
}