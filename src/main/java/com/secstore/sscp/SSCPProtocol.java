package com.secstore.sscp;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class SSCPProtocol
{
    public static enum Version
    {
        SSCP1("RSA", "ECB/PKCS1Padding", 1024, 1024/8-11),
        SSCP2("AES", "ECB/PKCS5Padding", 128, 2048);
        
        public static final int LENGTH = values().length;
        
        private final String algorithm;
        private final String config;
        private final int keySize;
        private final int maxBlockSize;
        
        private Version(String algorithm, String config, int keySize, int maxBlockSize)
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
        
        public SecretKey generateSecretKey()
        {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
                
                keyGenerator.init(keySize);
                
                return keyGenerator.generateKey();
            }
            
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalArgumentException("algorithm invalid");
            }
        }
        
        public KeyPair generateKeyPair()
        {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
                
                keyPairGenerator.initialize(keySize);
                
                return keyPairGenerator.generateKeyPair();
            }
            
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalArgumentException("algorithm invalid");
            }
        }
        
        public SecretKey generateSecretKey(byte[] keyBytes)
        {
            return new SecretKeySpec(keyBytes, algorithm);
        }
        
        public PublicKey generatePublicKey(byte[] keyBytes)
        {
            KeyFactory keyFactory;
            
            try {
                keyFactory = KeyFactory.getInstance(algorithm);
            }
            
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalArgumentException("algorithm invalid");
            }
            
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes, algorithm);
            
            try {
                return keyFactory.generatePublic(keySpec);
            }
            
            catch (InvalidKeySpecException exception) {
                throw new IllegalArgumentException("key bytes invalid " + exception);
            }
        }
        
        public PrivateKey generatePrivateKey(byte[] keyBytes)
        {
            KeyFactory keyFactory;
            
            try {
                keyFactory = KeyFactory.getInstance(algorithm);
            }
            
            catch (NoSuchAlgorithmException exception) {
                throw new IllegalArgumentException("algorithm invalid");
            }
            
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes, algorithm);
            
            try {
                return keyFactory.generatePrivate(keySpec);
            }
            
            catch (InvalidKeySpecException exception) {
                throw new IllegalArgumentException("key bytes invalid " + exception);
            }
        }
    }
}
