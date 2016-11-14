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
 * TODO: Document usage.
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

    public char[] decryptPassword(final char[] pbePassword, final String encryptedPassword) throws IOException
    {
        StandardPBEStringEncryptor standardPBEStringEncryptor = getStandardPBEStringEncryptor(pbePassword);

        return standardPBEStringEncryptor.decrypt(encryptedPassword).toCharArray();
    }

    public String encryptPassword(final char[] pbePassword, final String plainTextPassword) throws IOException
    {
        StandardPBEStringEncryptor standardPBEStringEncryptor = getStandardPBEStringEncryptor(pbePassword);

        return standardPBEStringEncryptor.encrypt(plainTextPassword);
    }

    private StandardPBEStringEncryptor getStandardPBEStringEncryptor(final char[] pbePassword) throws IOException
    {
        StandardPBEStringEncryptor standardPBEStringEncryptor = new StandardPBEStringEncryptor();

        SimplePBEConfig config = getSimplePBEConfig();

        standardPBEStringEncryptor.setConfig(config);

        standardPBEStringEncryptor.setPasswordCharArray(pbePassword);
        return standardPBEStringEncryptor;
    }

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

