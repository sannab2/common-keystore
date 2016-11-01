/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore.encryption;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig;
import sun.security.x509.X509CertInfo;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Properties;

public class CreateKeyStore
{
    public static final String CERTIFICATE_VALIDITY = "dell.cpsd.keystore.certificate.validity";
    //TODO COMPLETE CREATING THE KEYSTORE, AND ADD JAVA DOCS
    public KeyStore createServiceKeyStore(final String serviceName)
    {
        Properties properties = null;
        KeyStore keyStore = null;

        try
        {
            // Load Properties File
            properties = EncryptionPropertiesConfig.loadProperties();
            keyStore = KeyStore.getInstance(properties.getProperty(EncryptionPropertiesConfig.PROPERTY_KEYSTORE_TYPE));
        }
        catch (IOException | KeyStoreException exception)
        {

        }

        return null;
    }

    //TODO COMPLETE CREATING THE CERTIFICATE, AND ADD JAVA DOCS
    public static X509Certificate createCertificate(final String alias, final KeyPair keyPair) throws IOException
    {
        //PrivateKey privateKey = keyPair.getPrivate();
        X509CertInfo certificateInfo = new X509CertInfo();

        LocalDateTime fromDate = LocalDateTime.now();
        LocalDateTime toDate = LocalDateTime.now().plusYears(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_VALIDITY)));

        //CertificateValidity certificateValidity = new CertificateValidity(fr)
        return null;
    }

}
