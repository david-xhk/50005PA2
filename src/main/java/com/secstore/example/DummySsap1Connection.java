package com.secstore.example;

import java.io.IOException;
import com.secstore.Logger;
import com.secstore.ssap.Ssap1_0;
import com.secstore.ssap.SsapProtocol.SsapProtocolException;
import com.secstore.sscp.SscpProtocol;


/*
 * This class implements authentication protocol SSAP/1.0.
 * 
 * SSCP/2.0 is NOT supported.
 */
public class DummySsap1Connection extends DummySscpConnection
{
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
        
        SscpProtocol protocol = SscpProtocol.SSCP1;
        
        DummySsap1Connection server = new DummySsap1Connection(host, port, Type.SERVER);
        
        DummySsap1Connection client = new DummySsap1Connection(host, port, Type.CLIENT);
        
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
    
    public DummySsap1Connection(String host, int port, Type type)
        throws IOException
    {
        super(host, port, type);
    }
    
    @Override
    public void establishHandshake()
        throws IOException
    {
        try {
            switch (type) {
                case CLIENT:
                    Ssap1_0.doOpeningHandShake(this);
                    break;
                
                case SERVER:
                    Ssap1_0.doClosingHandShake(this);
                    break;
            }
        }
        
        catch (SsapProtocolException exception) {
            throw new IllegalStateException("ssap/1.0 handshake failed: " + exception);
        }
    }
}
