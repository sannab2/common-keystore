/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.dell.cpsd.common.keystore.config.EncryptionPropertiesConfig;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * This class provides various encryption utility methods that can be
 * used across various projects. It is essential that all the services
 * use the <code>{@link EncryptionUtility}</code> methods and not define
 * the methods in the respective projects.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since SINCE -TBD
 */
@Deprecated
public final class EncryptionUtility
{
    private static final String ENCRYPTION_KEY_SIZE_PROPERTY = "dell.cpsd.keystore.encryption.keysize";
    private static final String SECURE_RANDOM_CONSTANT       = "dell.cpsd.keystore.secure.random.constant";

    /**
     * Default Constructor - Scope is Private
     */
    private EncryptionUtility()
    {
        // Default Private Constructor
        // Added just to hide the class instantiation
    }

    /**
     * <p>
     * This method generates the KeyPairGenerator provided the encryption algorithm.
     * Ideally this method should be called first unless the client already has
     * the KeyPairGenerator instance.
     * </p>
     * <p>
     * It can be used to generate the Asymmetric key pair containing public and private key.
     * </p>
     *
     * @param algorithm Encryption Algorithm
     * @return keyPairGenerator
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws IOException IOException
     */
    public static KeyPairGenerator obtainKeyPairGenerator(final String algorithm) throws NoSuchAlgorithmException, IOException
    {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(ENCRYPTION_KEY_SIZE_PROPERTY)),
                SecureRandom.getInstance(EncryptionPropertiesConfig.loadProperties().getProperty(SECURE_RANDOM_CONSTANT)));
        return keyPairGenerator;
    }

    /**
     * This is one of the overloaded method which returns the KeyPair instance.
     * It takes KeyPairGenerator as an argument. If the KeyPairGenerator instance
     * is not available then either obtain the KeyPairGenerator instance by
     * calling <code>{@link EncryptionUtility#obtainKeyPairGenerator(String)}</code>
     * or directly call the overloaded method <code>{@link EncryptionUtility#obtainKeyPair(String)}</code>
     * if encryption algorithm and key size are known
     *
     * @param keyPairGenerator Key Pair Generator
     * @return KeyPair
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @see EncryptionUtility#obtainKeyPair(String)
     */
    public static KeyPair obtainKeyPair(final KeyPairGenerator keyPairGenerator) throws NoSuchAlgorithmException
    {
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * This is one of the overloaded methods which returns the KeyPair instance.
     * It takes encryption algorithm as an argument. The method internally
     * calls the <code>{@link EncryptionUtility#obtainKeyPairGenerator(String)}</code>
     * method to generate the KeyPairGenerator then generate the KeyPair from it.
     *
     * @param algorithm Encryption Algorithm
     * @return KeyPair
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws IOException IOException
     * @see EncryptionUtility#obtainKeyPair(KeyPairGenerator)
     */
    public static KeyPair obtainKeyPair(final String algorithm) throws NoSuchAlgorithmException, IOException
    {
        return obtainKeyPairGenerator(algorithm).generateKeyPair();
    }

    /**
     * This method returns the public key and takes KeyPairGenerator as an argument.
     * If KeyPairGenerator instance is not available, the overloaded method
     * <code>{@link EncryptionUtility#obtainPublicKey(String)}</code> which
     * takes encryption algorithm can be used.
     *
     * @param keyPairGenerator KeyPairGenerator
     * @return PublicKey
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @see EncryptionUtility#obtainPublicKey(String)
     */
    public static PublicKey obtainPublicKey(final KeyPairGenerator keyPairGenerator) throws NoSuchAlgorithmException
    {
        return keyPairGenerator.generateKeyPair().getPublic();
    }

    /**
     * This is an overloaded method and returns the public key. It takes
     * encryption algorithm as an argument. If KeyGeneratorInstance has
     * already been obtained then the overloaded method
     * <code>{@link EncryptionUtility#obtainPublicKey(KeyPairGenerator)}</code>
     * can be called.
     *
     * @param algorithm Encryption Algorithm
     * @return PublicKey
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws IOException IOException
     * @see EncryptionUtility#obtainPublicKey(KeyPairGenerator)
     */
    public static PublicKey obtainPublicKey(final String algorithm) throws NoSuchAlgorithmException, IOException
    {
        return obtainKeyPairGenerator(algorithm).generateKeyPair().getPublic();
    }

    /**
     * This method generates the public key string from the given public key.
     * It uses X.509 encoding standard to encode the public key into byte array
     * and uses <code>{@link Base64}</code> encoding to encode the byte array to string.
     *
     * @param publicKey the public key
     * @return public key encoded string
     */
    public static String generatePublicKeyString(final PublicKey publicKey)
    {
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        final byte[] encoded = x509EncodedKeySpec.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * This method derives the public key from the public key string. It
     * takes public key string and the encryption algorithm as parameters. For
     * deriving the public key from public key string X.509 encoding spec is used.
     * The library uses <code>{@link Base64}</code> for encoding and decoding, and
     * its recommended that all projects should follow same encoding and decoding
     * standards.
     *
     * @param publicKeyString the public key string
     * @param algorithm       the encryption algorithm
     * @return the public key
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException  InvalidKeySpecException
     */
    public static PublicKey derivePublicKeyFromString(final String publicKeyString, final String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        final byte[] decoded = Base64.getDecoder().decode(publicKeyString);
        final EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decoded);
        return keyFactory.generatePublic(pubKeySpec);
    }

    /**
     * This method converts the plain text to the cipher text. It takes multiple arguments:
     * The public key is used for text ciphering, and encryption algorithm is required for
     * generating the <code>{@link Cipher}</code> instance which converts the plain text
     * to cipher text and uses <b>UTF-8</b> encoding format.
     *
     * @param publicKey the public key
     * @param text      plain text to be encrypted
     * @param algorithm the encryption algorithm
     * @return cipher text - byte array
     * @throws NoSuchAlgorithmException     NoSuchAlgorithmException
     * @throws NoSuchPaddingException       NoSuchPaddingException
     * @throws InvalidKeyException          InvalidKeyException
     * @throws IllegalBlockSizeException    IllegalBlockSizeException
     * @throws BadPaddingException          BadPaddingException
     * @throws UnsupportedEncodingException UnsupportedEncodingException
     */
    public static String cipherText(final PublicKey publicKey, final String text, final String algorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            IOException
    {
        final Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        byte[] encodedByte = Base64.getEncoder().encode(cipherText);
        return new String(encodedByte, StandardCharsets.UTF_8);
    }

    /**
     * This method deciphers the cipher text using the private key of the independent services.
     * The method takes multiple arguments like encryption algorithm, private key, cipher text.
     * The algorithm type is required for obtaining the Cipher instance required to decrypt the
     * cipher text using the private key of the respective service.
     *
     * @param privateKey the private key
     * @param cipherText the cipher text
     * @param algorithm  the algorithm
     * @return deciphered text in string format
     * @throws NoSuchAlgorithmException  NoSuchAlgorithmException
     * @throws NoSuchPaddingException    NoSuchPaddingException
     * @throws InvalidKeyException       InvalidKeyException
     * @throws IllegalBlockSizeException IllegalBlockSizeException
     * @throws BadPaddingException       BadPaddingException
     * @throws IOException               IOException
     */
    public static String decipherText(final PrivateKey privateKey, final String cipherText, final String algorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            IOException
    {
        final Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedByteText = Base64.getDecoder().decode(cipherText);
        return new String(cipher.doFinal(decodedByteText));
    }
}
