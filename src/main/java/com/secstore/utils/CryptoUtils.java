package com.secstore.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class CryptoUtils
{
    public static final String base64Encode(byte[] bytes)
    {
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    public static final byte[] base64Decode(String string)
    {
        return Base64.getDecoder().decode(string);
    }
    
    public static final Cipher generateCipher(String algorithm, String config)
    {
        try {
            return Cipher.getInstance(algorithm + "/" + config);
        }
        
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalArgumentException("algorithm invalid: " + exception);
        }
        
        catch (NoSuchPaddingException exception) {
            throw new IllegalArgumentException("padding invalid: " + exception);
        }
    }
    
    public static final void initializeCipher(Cipher cipher, int mode, Key key)
    {
        try {
            synchronized (cipher) {
                cipher.init(mode, key);
            }
        }
        
        catch (InvalidKeyException exception) {
            throw new IllegalArgumentException("key invalid: " + exception);
        }
    }
    
    public static final byte[] encryptBytes(Cipher cipher, byte[] bytes)
    {
        try {
            synchronized (cipher) {
                return cipher.doFinal(bytes);
            }
        }
        
        catch (IllegalBlockSizeException exception) {
            throw new IllegalArgumentException("block size invalid: " + exception);
        }
        
        catch (BadPaddingException exception) {
            throw new IllegalArgumentException("padding invalid: " + exception);
        }
    }
    
    public static final byte[] decryptBytes(Cipher cipher, byte[] bytes)
    {
        try {
            synchronized (cipher) {
                return cipher.doFinal(bytes);
            }
        }
        
        catch (IllegalBlockSizeException exception) {
            throw new IllegalArgumentException("block size invalid: " + exception);
        }
        
        catch (BadPaddingException exception) {
            throw new IllegalArgumentException("padding invalid: " + exception);
        }
    }
    
    public static final X509Certificate generateCertificate(InputStream inputStream)
    {
        try {
            return (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(inputStream);
        }
        
        catch (CertificateException exception) {
            throw new IllegalStateException("certificate exception: " + exception);
        }
    }
    
    public static final X509Certificate generateCertificate(Path path)
    {
        try {
            return generateCertificate(Files.newInputStream(path));
        }
        
        catch (IOException exception) {
            throw new IllegalStateException("IO exception: " + exception);
        }
    }
    
    public static final X509Certificate generateCertificate(String string)
    {
        return generateCertificate(new ByteArrayInputStream(string.getBytes()));
    }
    
    public static final SecretKey generateSecretKey(String algorithm, int keySize)
    {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            
            keyGenerator.init(keySize);
            
            return keyGenerator.generateKey();
        }
        
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalArgumentException("algorithm invalid: " + exception);
        }
    }
    
    public static final KeyPair generateKeyPair(String algorithm, int keySize)
    {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            
            keyPairGenerator.initialize(keySize);
            
            return keyPairGenerator.generateKeyPair();
        }
        
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalArgumentException("algorithm invalid: " + exception);
        }
    }
    
    public static final SecretKey generateSecretKey(String algorithm, byte[] keyBytes)
    {
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    public static final PublicKey generatePublicKey(String algorithm, byte[] keyBytes)
    {
        KeyFactory keyFactory;
        
        try {
            keyFactory = KeyFactory.getInstance(algorithm);
        }
        
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalArgumentException("algorithm invalid: " + exception);
        }
        
        EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes, algorithm);
        
        try {
            return keyFactory.generatePublic(keySpec);
        }
        
        catch (InvalidKeySpecException exception) {
            throw new IllegalArgumentException("key bytes invalid " + exception);
        }
    }
    
    public static final PrivateKey generatePrivateKey(String algorithm, byte[] keyBytes)
    {
        KeyFactory keyFactory;
        
        try {
            keyFactory = KeyFactory.getInstance(algorithm);
        }
        
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalArgumentException("algorithm invalid: " + exception);
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
