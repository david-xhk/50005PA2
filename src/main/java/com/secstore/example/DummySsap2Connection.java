package com.secstore.example;

import static com.secstore.Logger.log;
import java.io.IOException;
import com.secstore.ssap.Ssap2_0;
import com.secstore.ssap.SsapProtocol.SsapProtocolException;
import com.secstore.sscp.SscpProtocol;


public class DummySsap2Connection extends DummySsap1Connection
{
    public static final String[] FILE_NAMES = new String[] {
        "Video.mp4"
//        "sceneries.jpg"
//        "1000.txt",
//        "10000.txt",
//        "100000.txt",
//        "200.txt",
//        "500.txt",
//        "5000.txt",
//        "50000.txt",
//        "buggy.txt",
    };
    
    public DummySsap2Connection(String host, int port, Type type)
        throws IOException
    {
        super(host, port, type);
    }
    
    public static void main(String[] args)
        throws IOException
    {
        String host = "localhost";
        
        int port = 50000;
        
        String[] fileNames = (args.length > 0) ? args : FILE_NAMES;
        
        SscpProtocol protocol = SscpProtocol.SSCP2;
        
        DummySsap2Connection server = new DummySsap2Connection(host, port, Type.SERVER);
        
        DummySsap2Connection client = new DummySsap2Connection(host, port, Type.CLIENT);
        
        start(new IORunnable(server)
        {
            @Override
            void run(DummySscpConnection connection)
                throws IOException
            {
                connection.connect();
                
                connection.establishHandshake();
                
                waitNSeconds(1);
                
                upgradeToSscp2Connection(connection);
                
                waitNSeconds(1);
                
                connection.setProtocol(protocol);
                
                for (String fileName : fileNames) {
                    
                    String filePath = RESOURCES + "/" + fileName;
                    
                    log("Server uploading " + filePath);
                    
                    long start = System.currentTimeMillis();
                    
                    connection.uploadFrom(filePath);
                    
                    long end = System.currentTimeMillis();
                    
                    log("Server finished uploading " + fileName + "!");
                    
                    log("Time taken: " + (end - start) + " ms");
                    
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
                
                upgradeToSscp2Connection(connection);
                
                waitNSeconds(1);
                
                connection.setProtocol(protocol);
                
                for (String fileName : fileNames) {
                    
                    String filePath = RESULTS + "/" + fileName;
                    
                    log("Client downloading " + filePath);
                    
                    long start = System.currentTimeMillis();
                    
                    connection.downloadTo(filePath);
                    
                    long end = System.currentTimeMillis();
                    
                    log("Client finished downloading " + fileName + "!");
                    
                    log("Time taken: " + (end - start) + " ms");
                    
                    waitNSeconds(3);
                }
            }
        });
    }
    
    public static void upgradeToSscp2Connection(DummySscpConnection connection)
        throws IOException
    {
        try {
            switch (connection.type) {
                case CLIENT:
                    Ssap2_0.doOpeningHandShake(connection);
                    break;
                
                case SERVER:
                    Ssap2_0.doClosingHandShake(connection);
                    break;
            }
        }
        
        catch (SsapProtocolException exception) {
            throw new IllegalStateException("ssap/2.0 handshake failed: " + exception);
        }
    }
}
