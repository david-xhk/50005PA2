package com.secstore.sscp;

import com.secstore.utils.CryptoUtils;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;


public enum SscpProtocol
{
    DEFAULT,
    SSCP1("RSA", "ECB/PKCS1Padding", 1024, 117),
    SSCP2("AES", "ECB/PKCS5Padding", 128, 8192);
    
    public static final SscpProtocol[] PROTOCOLS;
    
    static {
        SscpProtocol[] protocols = SscpProtocol.values();
        
        PROTOCOLS = new SscpProtocol[protocols.length - 1];
        
        System.arraycopy(protocols, 1, PROTOCOLS, 0, protocols.length - 1);
    }
    
    public static final int DEFAULT_BLOCK_SIZE = 8192;
    public static final Charset CHARSET = StandardCharsets.UTF_8;
    
    private final String algorithm;
    private final String config;
    private final Integer keySize;
    private final Integer maxBlockSize;
    
    private SscpProtocol()
    {
        this(null, null, null, DEFAULT_BLOCK_SIZE);
    }
    
    private SscpProtocol(String algorithm, String config, Integer keySize, Integer maxBlockSize)
    {
        this.algorithm = algorithm;
        this.config = config;
        this.keySize = keySize;
        this.maxBlockSize = maxBlockSize;
    }
    
    public String getAlgorithm()
    {
        return algorithm;
    }
    
    public String getConfig()
    {
        return config;
    }
    
    public int getKeySize()
    {
        return keySize;
    }
    
    public int getMaxBlockSize()
    {
        return maxBlockSize;
    }
    
    public boolean isNotDefault()
    {
        return (ordinal() > 0);
    }
    
    @Override
    public String toString()
    {
        switch (this) {
            case SSCP1:
                return "SSCP/1.0";
            
            case SSCP2:
                return "SSCP/2.0";
            
            case DEFAULT:
            default:
                return "DEFAULT";
        }
    }
    
    public Cipher generateCipher()
    {
        return CryptoUtils.generateCipher(algorithm, config);
    }
    
    public SecretKey generateSecretKey()
    {
        return CryptoUtils.generateSecretKey(algorithm, keySize);
    }
    
    public SecretKey generateSecretKey(byte[] keyBytes)
    {
        return CryptoUtils.generateSecretKey(algorithm, keyBytes);
    }
    
    public KeyPair generateKeyPair()
    {
        return CryptoUtils.generateKeyPair(algorithm, keySize);
    }
    
    public PublicKey generatePublicKey(byte[] keyBytes)
    {
        return CryptoUtils.generatePublicKey(algorithm, keyBytes);
    }
    
    public PrivateKey generatePrivateKey(byte[] keyBytes)
    {
        return CryptoUtils.generatePrivateKey(algorithm, keyBytes);
    }
}
