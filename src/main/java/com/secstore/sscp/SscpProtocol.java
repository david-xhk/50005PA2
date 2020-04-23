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
    
    public static final SscpProtocol[] PROTOCOLS = new SscpProtocol[] { SscpProtocol.SSCP1, SscpProtocol.SSCP2 };
    public static final int LENGTH = PROTOCOLS.length;
    public static final int DEFAULT_BLOCK_SIZE = 8192;
    public static final Charset CHARSET = StandardCharsets.UTF_8;
    public static final byte[] EOT_MESSAGE = "-----END OF TRANSMISSION-----".getBytes(CHARSET);
    public static final byte EOT_BYTE = 0x04;
    
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
