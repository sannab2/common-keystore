/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore.encryption;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.RandomSaltGenerator;
import org.jasypt.salt.SaltGenerator;

import java.io.IOException;
import java.util.Properties;

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
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 * </p>
 *
 * @since Vision 1.0.0
 */
public class PasswordEncryptionUtility
{
    private Properties properties;

    /**
     * This method will decrypt the previously encrypted password. It takes the
     * configuration password that was used to encrypt the password previously,
     * and the encrypted password itself.
     * <p>
     * <b>
     * Note: The service calling this method must be responsible for removing
     * the decrypted password from the memory.
     * </b>
     * </p>
     *
     * @param pbePassword       The password that is stored for the encryptor configuration.
     *                          This is the same password that was used when the plain text
     *                          password was encrypted.
     * @param encryptedPassword This is the encrypted password in the configuration file
     * @return decrypted password as character array
     * @throws IOException IO Exception
     */
    public char[] decryptPassword(final char[] pbePassword, final String encryptedPassword) throws IOException
    {
        StandardPBEStringEncryptor standardPBEStringEncryptor = getStandardPBEStringEncryptor(pbePassword);

        return standardPBEStringEncryptor.decrypt(encryptedPassword).toCharArray();
    }

    /**
     * This method is just for the demonstration purpose, it encrypts the
     * plain text password using the configuration password that it
     * receives. This method should not be used the production environment,
     * as it receives the password in {@link String} format. For encrypting
     * the passwords, the command line utility can be used, or it can simply
     * be used to generate the encrypted passwords for the configuration file.
     * <p>
     * <b>
     * Note: This method encrypts the password based on the algorithm,
     * hashing iterations, salt etc and will generate a different encrypted
     * password each time. It doesn't matter if it produces different
     * encrypted passwords using the same plain text password and configuration
     * password. As long as the configuration password is same, the encrypted
     * password can be decrypted.
     * </b>
     * </p>
     *
     * @param pbePassword       The password that is stored for the encryptor
     *                          configuration. This password must be used to
     *                          decrypt the encrypted password later on.
     * @param plainTextPassword Plain text password to be encrypted.
     * @return Encrypted Password
     * @throws IOException IO Exception
     */
    public String encryptPassword(final char[] pbePassword, final String plainTextPassword) throws IOException
    {
        StandardPBEStringEncryptor standardPBEStringEncryptor = getStandardPBEStringEncryptor(pbePassword);

        return standardPBEStringEncryptor.encrypt(plainTextPassword);
    }

    /**
     * The method generates the {@link StandardPBEStringEncryptor} instance.
     * This method is called internally.
     *
     * @param pbePassword The password that is stored for the encryptor
     *                    configuration. This password must be used to
     *                    decrypt the encrypted password later on.
     * @return StandardPBEStringEncryptor instance
     * @throws IOException IO Exception
     * @see PasswordEncryptionUtility#encryptPassword(char[], String)
     * @see PasswordEncryptionUtility#decryptPassword(char[], String)
     * @see PasswordEncryptionUtility#getSimplePBEConfig()
     */
    private StandardPBEStringEncryptor getStandardPBEStringEncryptor(final char[] pbePassword) throws IOException
    {
        StandardPBEStringEncryptor standardPBEStringEncryptor = new StandardPBEStringEncryptor();

        SimplePBEConfig config = getSimplePBEConfig();

        standardPBEStringEncryptor.setConfig(config);

        standardPBEStringEncryptor.setPasswordCharArray(pbePassword);
        return standardPBEStringEncryptor;
    }

    /**
     * This method returns the configuration instance, where the
     * number of hashing iterations, encryption algorithm, salt key
     * length is specified.
     * This method is called internally.
     *
     * @return SimplePBEConfig instance
     * @throws IOException IO Exception
     * @see PasswordEncryptionUtility#getStandardPBEStringEncryptor(char[])
     */
    private SimplePBEConfig getSimplePBEConfig() throws IOException
    {
        properties = EncryptionPropertiesConfig.loadProperties();
        SimplePBEConfig config = new SimplePBEConfig();
        config.setKeyObtentionIterations(properties.getProperty("dell.cpsd.keystore.hashing.iterations.count"));
        config.setAlgorithm(properties.getProperty("dell.cpsd.keystore.pbe.encryption.algorithm"));
        SaltGenerator saltGenerator = new RandomSaltGenerator();
        saltGenerator.generateSalt(Integer.parseInt(properties.getProperty("dell.cpsd.keystore.salt.generator.bytes.length")));
        config.setSaltGenerator(saltGenerator);
        return config;
    }
}

