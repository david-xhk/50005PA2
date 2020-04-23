package com.secstore.example;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
import com.secstore.Logger;
import com.secstore.sscp.SscpConnection;
import com.secstore.sscp.SscpProtocol;


/*
 * This class bypasses all authentication protocols SSAP/1.0 and SSAP/2.0.
 * 
 * It is for testing SSCP/1.0 and SSCP/2.0 without interference of SSAP.
 */
public class DummySscpConnection extends SscpConnection
{
    public static final String RESOURCES = "src/main/resources";
    public static final String RESULTS = "src/main/results";
    
    /* Uncomment the file(s) you want to see transferred
     *
     * More files can be added here by saving them in src/main/resources
     */
    public static final String[] FILE_NAMES = new String[] {
//        "100.txt"
//        "1000.txt"
//        "10000.txt"
//        "100000.txt"
//        "200.txt"
//        "500.txt"
//        "5000.txt"
//        "50000.txt"
//        "buggy.txt"
//        "bytefilelarge"
//        "bytefilemedium"
//        "bytefilesmall"
//        "campus.jpg"
//        "circus.mp3"
//        "class-AudioClip.html"
//        "demo.mov"
//        "docs.pdf"
//        "guitar.wav"
//        "large.txt"
//        "medium.txt"
//        "output_cave.wav"
//        "preprintsample.pdf"
//        "sceneries.jpg"
//        "small.txt"
//        "tenor.gif"
    };
    
    /*
     * Change to true if verbose output is needed
     */
    @Override
    public boolean debug()
    {
        return false;
    }
    
    public static void main(String[] args)
        throws IOException
    {
        String host = "localhost";
        
        int port = 50000;
        
        String[] fileNames = (args.length > 0) ? args : FILE_NAMES;
        
        SscpProtocol protocol = SscpProtocol.DEFAULT;
        
        DummySscpConnection server = new DummySscpConnection(host, port, Type.SERVER);
        
        DummySscpConnection client = new DummySscpConnection(host, port, Type.CLIENT);
        
        start(new IORunnable(server)
        {
            @Override
            void run(DummySscpConnection connection)
                throws IOException
            {
                connection.connect();
                
                connection.establishHandshake();
                
                waitNSeconds(1);
                
                connection.setProtocol(protocol);
                
                for (String fileName : fileNames) {
                    
                    String filePath = RESOURCES + "/" + fileName;
                    
                    Logger.log("Server uploading " + filePath);
                    
                    long start = System.currentTimeMillis();
                    
                    connection.uploadFrom(filePath);
                    
                    long end = System.currentTimeMillis();
                    
                    Logger.log("Server finished uploading " + fileName + "!");
                    
                    Logger.log("Time taken: " + (end - start) + " ms");
                    
                    waitNSeconds(3);
                }
            }
        });
        
        start(new IORunnable(client)
        {
            @Override
            void run(DummySscpConnection connection)
                throws IOException
            {
                connection.connect();
                
                connection.establishHandshake();
                
                waitNSeconds(1);
                
                connection.setProtocol(protocol);
                
                for (String fileName : fileNames) {
                    
                    String filePath = RESULTS + "/" + fileName;
                    
                    Logger.log("Client downloading " + filePath);
                    
                    long start = System.currentTimeMillis();
                    
                    connection.downloadTo(filePath);
                    
                    long end = System.currentTimeMillis();
                    
                    Logger.log("Client finished downloading " + fileName + "!");
                    
                    Logger.log("Time taken: " + (end - start) + " ms");
                    
                    waitNSeconds(3);
                }
            }
        });
    }
    
    private static final PublicKey serverPublicKey;
    private static final PrivateKey serverPrivateKey;
    private static final SecretKey symmetricKey;
    
    static {
        KeyPair keyPair = SscpProtocol.SSCP1.generateKeyPair();
        
        serverPublicKey = keyPair.getPublic();
        serverPrivateKey = keyPair.getPrivate();
        symmetricKey = SscpProtocol.SSCP2.generateSecretKey();
    }
    
    private String host;
    private int port;
    protected Type type;
    
    public DummySscpConnection(String host, int port, Type type)
        throws IOException
    {
        this.host = host;
        this.port = port;
        this.type = type;
    }
    
    public void connect()
        throws IOException
    {
        switch (type) {
            case CLIENT:
                Logger.log("Client connecting");
                
                connect(new Socket(host, port));
                
                Logger.log("Client connected to: " + getSocket());
                
                break;
            
            case SERVER:
                Logger.log("Starting server");
                
                ServerSocket server = new ServerSocket();
                
                server.bind(new InetSocketAddress(host, port));
                
                Logger.log("Server bound to: " + server.getInetAddress());
                
                try {
                    Logger.log("Server waiting to accept");
                    
                    Socket socket = server.accept();
                    
                    Logger.log("Server connected to: " + socket);
                    
                    connect(socket);
                }
                
                catch (IOException exception) {
                    exception.printStackTrace();
                }
                
                finally {
                    try {
                        server.close();
                        
                        Logger.log("Server closed");
                    }
                    
                    catch (IOException exception) {
                        exception.printStackTrace();
                    }
                }
                
                break;
        }
    }
    
    @Override
    public void establishHandshake()
        throws IOException
    {
        switch (type) {
            case SERVER:
                setKey(SscpProtocol.SSCP1, serverPrivateKey);
                break;
            
            case CLIENT:
                setKey(SscpProtocol.SSCP1, serverPublicKey);
                break;
            
            default:
                throw new IllegalStateException("unknown type");
        }
        
        setKey(SscpProtocol.SSCP2, symmetricKey);
    }
    
    public static void waitNSeconds(int N)
    {
        try {
            TimeUnit.SECONDS.sleep(N);
        }
        
        catch (InterruptedException exception) { }
    }
    
    public static void start(IORunnable runnable)
    {
        new Thread(runnable).start();
    }
    
    public static abstract class IORunnable
        implements Runnable
    {
        private DummySscpConnection connection;
        
        public IORunnable(DummySscpConnection connection)
        {
            this.connection = connection;
        }
        
        @Override
        public void run()
        {
            try {
                run(connection);
            }
            
            catch (IOException exception) {
                throw new IllegalStateException("IO exception: " + exception);
            }
        }
        
        abstract void run(DummySscpConnection connection) throws IOException;
    }
    
    public static enum Type { CLIENT, SERVER }
}