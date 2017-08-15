/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.dell.cpsd.common.keystore.config.EncryptionPropertiesConfig;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This is the Password Based Encryption Utility class. The
 * purpose of this class is to decrypt the encrypted passwords
 * from the configuration file, so that they can be consumed by
 * the application.
 * <p>
 * <i>
 * This will ensure that that the configuration passwords
 * are not lying in the plain text in any of the
 * configuration files.
 * </i>
 * </p>
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.1
 * @since 1.0
 */
@Deprecated
public class PasswordEncryptionUtility
{
    private static Properties properties;
    private static final Logger logger = Logger.getLogger("PasswordEncryptionUtility");

    static
    {
        try
        {
            properties = EncryptionPropertiesConfig.loadProperties();
        }
        catch (IOException exception)
        {
            logger.log(Level.SEVERE, exception.getMessage());
        }
        logger.log(Level.INFO, "Properties Loaded");
    }

    private static String bytesToHex(byte[] hash)
    {
        return DatatypeConverter.printHexBinary(hash);
    }

    /**
     * This method gives the secret key Hex which is used
     * to encrypt and decrypt the passwords or texts.
     * <p>
     * <b>
     * Note: The same secret key is used to encrypt and decrypt
     * the text, otherwise and exception will be thrown.
     * So, the secret key that was used to encrypt the password
     * must be used to decrypt the password, and the secret key
     * hex must be stored in the properties file.
     * </b>
     * </p>
     *
     * @return Secret Key Hex - Store it in properties file.
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     */
    public String getSecretKeyHex() throws NoSuchAlgorithmException
    {
        return DatatypeConverter.printHexBinary(getSecretEncryptionKey().getEncoded());
    }

    /**
     * This method returns the secret key.
     *
     * @return Secret Key
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     */
    private SecretKey getSecretEncryptionKey() throws NoSuchAlgorithmException
    {
        final KeyGenerator generator = KeyGenerator.getInstance(properties.getProperty("dell.cpsd.keystore.password.encryption.algorithm"));
        generator.init(Integer.parseInt(properties.getProperty("dell.cpsd.keystore.password.encryption.keysize")));
        return generator.generateKey();
    }

    /**
     * This method returns the encrypted password that goes
     * in the properties file.
     *
     * @param plainText    Password to be encrypted
     * @param secretKeyHex Secret Key Hex
     * @return Encrypted text that goes in properties file
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws NoSuchPaddingException NoSuchPaddingException
     * @throws InvalidKeyException InvalidKeyException
     * @throws IllegalBlockSizeException IllegalBlockSizeException
     * @throws BadPaddingException BadPaddingException
     */
    @Deprecated
    public String encryptText(final String plainText, final String secretKeyHex)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        final Cipher cipher = Cipher.getInstance(properties.getProperty("dell.cpsd.keystore.password.encryption.algorithm"));
        final SecretKey secretKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(secretKeyHex),
                properties.getProperty("dell.cpsd.keystore.password.encryption.algorithm"));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] encodedByte = Base64.getEncoder().encode(cipherText);
        return new String(encodedByte, StandardCharsets.UTF_8);
    }

    /**
     * This method is called when the passwords need to be decrypted
     * before use.
     *
     * @param cipherText   Encrypted password that is in the properties file
     * @param secretKeyHex The secret key hex that is in the properties file
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws NoSuchPaddingException NoSuchPaddingException
     * @throws InvalidKeyException InvalidKeyException
     * @throws IllegalBlockSizeException IllegalBlockSizeException
     * @throws BadPaddingException BadPaddingException
     * @return Decrypted password
     */
    @Deprecated
    public String decryptText(final String cipherText, final String secretKeyHex)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        final Cipher cipher = Cipher.getInstance(properties.getProperty("dell.cpsd.keystore.password.encryption.algorithm"));
        final SecretKey secretKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(secretKeyHex),
                properties.getProperty("dell.cpsd.keystore.password.encryption.algorithm"));
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedByteText = Base64.getDecoder().decode(cipherText);
        byte[] bytePlainText = cipher.doFinal(decodedByteText);
        return new String(bytePlainText);
    }

}

