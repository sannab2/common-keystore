/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig;
import org.junit.Assert;
import org.junit.Test;

/**
 * This is the test class for Encryption Properties.
 * There should be a separate unit test case for each of the property
 * defined in the properties file.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * <p/>
 *
 * @version 1.0
 * @since SINCE-TBD
 */
public class EncryptionPropertiesTest
{
    public static final  String ENCRYPTION_ALGORITHM          = "RSA";
    private static final int    ENCRYPTION_KEY_SIZE           = 2048;
    private static final String KEYSTORE_TYPE                 = "PKCS12";
    private static final String ENCODING_TYPE                 = "UTF-8";
    private static final int    CERTIFICATE_VALIDITY          = 1;
    private static final int    CERTIFICATE_SNO_BIT_SIZE      = 128;
    private static final String CERTIFICATE_SIGNING_ALGORITHM = "MD5WithRSA";
    private static final String KEYSTORE_OUTPUT_TYPE          = ".p12";
    private static final String HASHING_ITERATIONS_COUNT      = "1000";
    private static final String PBE_ENCRYPTION_ALGORITHM      = "PBEWITHMD5ANDDES";
    private static final int    SALT_GENERATOR_BYTE_LENGTH    = 32;

    private static final String ENCRYPTION_KEY_SIZE_PROPERTY           = "dell.cpsd.keystore.encryption.keysize";
    private static final String ENCRYPTION_ALGORITHM_PROPERTY          = "dell.cpsd.keystore.encryption.algorithm";
    private static final String KEYSTORE_TYPE_PROPERTY                 = "dell.cpsd.keystore.type";
    private static final String ENCRYPTION_ENCODING_PROPERTY           = "dell.cpsd.keystore.encryption.encoding";
    private static final String CERTIFICATE_VALIDITY_PROPERTY          = "dell.cpsd.keystore.certificate.validity";
    private static final String CERTIFICATE_SNO_BIT_SIZE_PROPERTY      = "dell.cpsd.keystore.certificate.sn.bits.size";
    private static final String CERTIFICATE_SIGNING_ALGORITHM_PROPERTY = "dell.cpsd.keystore.certificate.signing.algorithm";
    private static final String KEYSTORE_OUTPUT_TYPE_PROPERTY          = "dell.cpsd.keystore.certificate.output.type";
    private static final String HASHING_ITERATIONS_COUNT_PROPERTY      = "dell.cpsd.keystore.hashing.iterations.count";
    private static final String PBE_ENCRYPTION_ALGORITHM_PROPERTY      = "dell.cpsd.keystore.pbe.encryption.algorithm";
    private static final String SALT_GENERATOR_BYTE_LENGTH_PROPERTY    = "dell.cpsd.keystore.salt.generator.bytes.length";

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
    public void test_Property_Certificate_Sno_Bit_Size() throws Exception
    {
        Assert.assertEquals(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_SNO_BIT_SIZE_PROPERTY)),
                CERTIFICATE_SNO_BIT_SIZE);
    }

    @Test
    public void test_Property_Certificate_Signing_Algorithm() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_SIGNING_ALGORITHM_PROPERTY),
                CERTIFICATE_SIGNING_ALGORITHM);
    }

    @Test
    public void test_Property_KeyStore_Output_Type() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(KEYSTORE_OUTPUT_TYPE_PROPERTY), KEYSTORE_OUTPUT_TYPE);
    }

    @Test
    public void test_Property_hashing_iterations_count() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(HASHING_ITERATIONS_COUNT_PROPERTY),
                HASHING_ITERATIONS_COUNT);
    }

    @Test
    public void test_Property_pbe_encryption_algorithm() throws Exception
    {
        Assert.assertEquals(EncryptionPropertiesConfig.loadProperties().getProperty(PBE_ENCRYPTION_ALGORITHM_PROPERTY),
                PBE_ENCRYPTION_ALGORITHM);
    }

    @Test
    public void test_Property_salt_generator_byte_length() throws Exception
    {
        Assert.assertEquals(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(SALT_GENERATOR_BYTE_LENGTH_PROPERTY)),
                SALT_GENERATOR_BYTE_LENGTH);
    }
}
