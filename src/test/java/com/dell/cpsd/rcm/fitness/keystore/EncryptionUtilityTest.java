/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig;
import com.dell.cpsd.rcm.fitness.keystore.encryption.EncryptionUtility;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * This is the test class for EncryptionUtility class.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * <p/>
 *
 * @version 1.0
 * @since SINCE-TBD
 */
public class EncryptionUtilityTest
{
    public static final String ENCRYPTION_ALGORITHM = "RSA";
    public static final int    ENCRYPTION_KEY_SIZE  = 2048;
    public static final String KEYSTORE_TYPE        = "PKCS12";
    public static final String ENCODING_TYPE        = "UTF-8";
    public static final int    CERTIFICATE_VALIDITY = 1;

    public static final String ENCRYPTION_KEY_SIZE_PROPERTY  = "dell.cpsd.keystore.encryption.keysize";
    public static final String ENCRYPTION_ALGORITHM_PROPERTY = "dell.cpsd.keystore.encryption.algorithm";
    public static final String KEYSTORE_TYPE_PROPERTY        = "dell.cpsd.keystore.type";
    public static final String ENCRYPTION_ENCODING_PROPERTY  = "dell.cpsd.keystore.encryption.encoding";
    public static final String CERTIFICATE_VALIDITY_PROPERTY = "dell.cpsd.keystore.certificate.validity";

    @Test(expected = NoSuchAlgorithmException.class)
    public void no_such_algorithm_exception() throws Exception
    {
        EncryptionUtility.obtainPublicKey("AES");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void invalid_key_specification_exception() throws Exception
    {
        PublicKey publicKey = EncryptionUtility.obtainPublicKey(ENCRYPTION_ALGORITHM);

        String publicKeyString = EncryptionUtility.generatePublicKeyString(publicKey);

        EncryptionUtility.derivePublicKeyFromString(publicKeyString, "DSA");
    }

    @Test
    public void test_Property_EncryptionAlgorithm() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(ENCRYPTION_ALGORITHM_PROPERTY), ENCRYPTION_ALGORITHM);
    }

    @Test
    public void test_Property_KeySize() throws Exception
    {
        Assert.assertEquals(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(ENCRYPTION_KEY_SIZE_PROPERTY)),
                ENCRYPTION_KEY_SIZE);
    }

    @Test
    public void test_Property_KeyStore_Type() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(KEYSTORE_TYPE_PROPERTY), KEYSTORE_TYPE);
    }

    @Test
    public void test_Property_Encoding_Type() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(ENCRYPTION_ENCODING_PROPERTY), ENCODING_TYPE);
    }

    @Test
    public void test_Property_Certificate_Validity() throws Exception
    {
        Assert.assertEquals(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_VALIDITY_PROPERTY)),
                CERTIFICATE_VALIDITY);
    }

    @Test
    public void compare_PublicKey_With_DerivedPublicKey() throws Exception
    {
        PublicKey publicKey = EncryptionUtility.obtainPublicKey(ENCRYPTION_ALGORITHM);

        String publicKeyString = EncryptionUtility.generatePublicKeyString(publicKey);

        PublicKey derivedPublicKey = EncryptionUtility.derivePublicKeyFromString(publicKeyString, ENCRYPTION_ALGORITHM);

        Assert.assertEquals(derivedPublicKey, publicKey);
    }

    @Test
    public void compare_CipherText_With_PlainText_NotSame() throws Exception
    {
        PublicKey publicKey = EncryptionUtility.obtainPublicKey(ENCRYPTION_ALGORITHM);

        String plainText = "unencryptedPassword";

        String cipherText = new String(EncryptionUtility.cipherText(publicKey, plainText, ENCRYPTION_ALGORITHM));

        Assert.assertNotEquals(plainText, cipherText);
        Assert.assertNotSame(cipherText, plainText);
    }

    @Test
    public void compare_CipherText_With_DecipherText_Same() throws Exception
    {
        KeyPair keyPair = EncryptionUtility.obtainKeyPair(ENCRYPTION_ALGORITHM);

        String plainText = "unencryptedPassword";

        byte[] cipherText = EncryptionUtility.cipherText(keyPair.getPublic(), plainText, ENCRYPTION_ALGORITHM);

        String decipherText = EncryptionUtility.decipherText(keyPair.getPrivate(), cipherText, ENCRYPTION_ALGORITHM);

        Assert.assertEquals(decipherText, plainText);
    }
}
