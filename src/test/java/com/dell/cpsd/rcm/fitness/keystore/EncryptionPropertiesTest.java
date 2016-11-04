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
    public static final String ENCRYPTION_ALGORITHM          = "RSA";
    public static final int    ENCRYPTION_KEY_SIZE           = 2048;
    public static final String KEYSTORE_TYPE                 = "PKCS12";
    public static final String ENCODING_TYPE                 = "UTF-8";
    public static final int    CERTIFICATE_VALIDITY          = 1;
    public static final int    CERTIFICATE_SNO_BIT_SIZE      = 128;
    public static final String CERTIFICATE_SIGNING_ALGORITHM = "MD5WithRSA";
    public static final String KEYSTORE_OUTPUT_TYPE          = ".p12";

    public static final String ENCRYPTION_KEY_SIZE_PROPERTY           = "dell.cpsd.keystore.encryption.keysize";
    public static final String ENCRYPTION_ALGORITHM_PROPERTY          = "dell.cpsd.keystore.encryption.algorithm";
    public static final String KEYSTORE_TYPE_PROPERTY                 = "dell.cpsd.keystore.type";
    public static final String ENCRYPTION_ENCODING_PROPERTY           = "dell.cpsd.keystore.encryption.encoding";
    public static final String CERTIFICATE_VALIDITY_PROPERTY          = "dell.cpsd.keystore.certificate.validity";
    public static final String CERTIFICATE_SNO_BIT_SIZE_PROPERTY      = "dell.cpsd.keystore.certificate.sn.bits.size";
    public static final String CERTIFICATE_SIGNING_ALGORITHM_PROPERTY = "dell.cpsd.keystore.certificate.signing.algorithm";
    public static final String KEYSTORE_OUTPUT_TYPE_PROPERTY          = "dell.cpsd.keystore.certificate.output.type";

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
}
