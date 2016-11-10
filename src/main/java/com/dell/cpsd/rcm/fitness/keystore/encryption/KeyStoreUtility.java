/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore.encryption;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * This class provides various key store utility methods that can be
 * used across various projects. It is essential that all the services
 * use the <code>{@link KeyStoreUtility}</code> methods and not define
 * the methods in the respective projects.
 * This class can be used for creating the key stores, loading the key
 * stores, storing keys or certificates, or retrieving the keys.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * <p/>
 *
 * @version 1.0
 * @since SINCE -TBD
 */
public final class KeyStoreUtility
{
    private static final String KEYSTORE_TYPE_PROPERTY                 = "dell.cpsd.keystore.type";
    private static final String KEYSTORE_OUTPUT_TYPE_PROPERTY          = "dell.cpsd.keystore.certificate.output.type";
    private static final String CERTIFICATE_VALIDITY_PROPERTY          = "dell.cpsd.keystore.certificate.validity";
    private static final String CERTIFICATE_SNO_BIT_SIZE_PROPERTY      = "dell.cpsd.keystore.certificate.sn.bits.size";
    private static final String CERTIFICATE_SIGNING_ALGORITHM_PROPERTY = "dell.cpsd.keystore.certificate.signing.algorithm";
    private static final String ENCRYPTION_ALGORITHM_PROPERTY          = "dell.cpsd.keystore.encryption.algorithm";

    public KeyStoreUtility()
    {
        // Default Constructor
    }

    /**
     * This method generates a new <i>PKCS12</i> KeyStore. The method
     * does not check if the key store has previously been previously
     * created or not. The parameters service name and key store path
     * are used to store the key store with the help of a password,
     * which is essential for the integrity of the key store. It is
     * essential that any service creating the key store must store
     * the password securely as it is required to access the key store.
     *
     * @param serviceName Requesting Service Name
     * @param keyStorePath Path to the Key store (/opt/dell/rcm-fitness/services/<service-name>/conf/keystore/
     * @param keyStorePassword Password to unlock the key store
     * @param keyAlias Alias used while storing the key, key is again retrieved using this alias
     * @param keyPassword Password used to retrieve the key
     * @return
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public KeyStore createServiceKeyStore(final String serviceName, final String keyStorePath, final char[] keyStorePassword,
            final String keyAlias, final char[] keyPassword)
            throws SignatureException, NoSuchProviderException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException
    {
        try
        {
            final KeyStore keyStore = KeyStore.getInstance(EncryptionPropertiesConfig.loadProperties().getProperty(KEYSTORE_TYPE_PROPERTY));

            //The input stream and password is null for creating the key store first time
            keyStore.load(null, null);

            final String keyStoreId = keyStorePath + "" + serviceName + EncryptionPropertiesConfig.loadProperties()
                    .getProperty(KEYSTORE_OUTPUT_TYPE_PROPERTY);

            updateKeyStore(keyPassword, keyAlias, keyStore);

            //Appends the key store path, service name, and key store name
            keyStore.store(new FileOutputStream(keyStoreId), keyStorePassword);

            return keyStore;
        }
        catch (KeyStoreException exception)
        {
            throw new KeyStoreException(exception);
        }
        catch (NoSuchAlgorithmException exception)
        {
            throw new NoSuchAlgorithmException(exception);
        }
        catch (CertificateException exception)
        {
            throw new CertificateException(exception);
        }
        catch (IOException exception)
        {
            throw new IOException(exception);
        }
    }

    /**
     * TODO JAVA DOCS
     *
     * @param keyPassword
     * @param keyAlias
     * @param keyStore
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CertificateException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws KeyStoreException
     */
    private void updateKeyStore(final char[] keyPassword, final String keyAlias, final KeyStore keyStore)
            throws NoSuchAlgorithmException, IOException, CertificateException, SignatureException, NoSuchProviderException,
            InvalidKeyException, KeyStoreException
    {
        final KeyPair keyPair = EncryptionUtility
                .obtainKeyPair(EncryptionPropertiesConfig.loadProperties().getProperty(ENCRYPTION_ALGORITHM_PROPERTY));
        final X509Certificate x509Certificate = createCertificate(keyAlias, keyPair);
        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyPassword, new X509Certificate[] {x509Certificate});
    }

    /**
     * TODO JAVA DOCS
     *
     * @param alias
     * @param keyPair
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    private X509Certificate createCertificate(final String alias, final KeyPair keyPair)
            throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException,
            InvalidKeyException
    {
        PrivateKey privateKey = keyPair.getPrivate();
        X509CertInfo certificateInfo = new X509CertInfo();

        Date fromDate = Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant());
        Date toDate = Date.from(LocalDateTime.now()
                .plusYears(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_VALIDITY_PROPERTY)))
                .atZone(ZoneId.systemDefault()).toInstant());

        CertificateValidity certificateValidity = new CertificateValidity(fromDate, toDate);
        BigInteger serialNumber = new BigInteger(
                Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_SNO_BIT_SIZE_PROPERTY)),
                new SecureRandom());
        X500Name issuerName = new X500Name("C=" + alias);
        X500Name subject = new X500Name("C=" + alias);

        certificateInfo.set(X509CertInfo.VALIDITY, certificateValidity);
        certificateInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        certificateInfo.set(X509CertInfo.SUBJECT, subject);
        certificateInfo.set(X509CertInfo.ISSUER, issuerName);
        certificateInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        certificateInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algorithm = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        certificateInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));
        X509CertImpl x509Cert = signCertificate(privateKey, certificateInfo);

        return x509Cert;
    }

    /**
     * TODO JAVA DOCS
     *
     * @param privateKey
     * @param certificateInfo
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IOException
     */
    private X509CertImpl signCertificate(final PrivateKey privateKey, final X509CertInfo certificateInfo)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException,
            IOException
    {
        // Sign the certificate
        X509CertImpl x509Cert = new X509CertImpl(certificateInfo);
        x509Cert.sign(privateKey, EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_SIGNING_ALGORITHM_PROPERTY));
        return x509Cert;
    }

    //TODO Complete the functionality
    private KeyStore loadKeyStore(final String pathToKeyStore, final char[] keyStorePassword) throws FileNotFoundException
    {
        try (InputStream fileInputStream = new FileInputStream(pathToKeyStore))
        {
            KeyStore keyStore = KeyStore.getInstance(EncryptionPropertiesConfig.loadProperties().getProperty(KEYSTORE_TYPE_PROPERTY));
            keyStore.load(fileInputStream, keyStorePassword);

            return keyStore;
        }
        catch (FileNotFoundException exception)
        {
            throw new FileNotFoundException(exception.getMessage());
        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException exception)
        {
            //TODO Handle or throw the exception properly
        }

        return null;
    }

    //TODO Complete the functionality
    public KeyPair getKeyPairFromKeyStore(final String pathToKeyStore, final char[] keyStorePassword, final char[] keyPassword,
            final String keyStoreAlias) throws FileNotFoundException
    {
        try
        {
            KeyStore keyStore = loadKeyStore(pathToKeyStore, keyStorePassword);

            Key key = generateKeyFromKeyStore(keyStore, keyStoreAlias, keyPassword);

            if (key instanceof PrivateKey)
            {
                Certificate certificate = keyStore.getCertificate(keyStoreAlias);

                PublicKey publicKey = certificate.getPublicKey();

                return new KeyPair(publicKey, (PrivateKey) key);
            }
        }
        catch (KeyStoreException exception)
        {
            //TODO Handle or throw the exception properly
            // Don't handle the exceptions
        }

        return null;
    }

    //TODO Complete the functionality
    public PublicKey getPublicKey(final String pathToKeyStore, final char[] keyStorePassword, final char[] keyPassword,
            final String keyStoreAlias) throws FileNotFoundException
    {
        try
        {
            KeyStore keyStore = loadKeyStore(pathToKeyStore, keyStorePassword);

            Key key = generateKeyFromKeyStore(keyStore, keyStoreAlias, keyPassword);

            if (key instanceof PrivateKey)
            {
                Certificate certificate = keyStore.getCertificate(keyStoreAlias);

                PublicKey publicKey = certificate.getPublicKey();

                return publicKey;
            }
        }
        catch (KeyStoreException exception)
        {
            //TODO Handle or throw the exception properly
            // Don't handle the exceptions
        }

        return null;
    }

    //TODO GENERATE THE KEY FROM KEYSTORE
    private Key generateKeyFromKeyStore(final KeyStore keyStore, final String keyStoreAlias, final char[] keyPassword)
    {
        try
        {
            return keyStore.getKey(keyStoreAlias, keyPassword);
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception)
        {
            //TODO
            // Don't handle the exceptions
        }
        return null;
    }

    /**
     * This method must be called by the service before instantiating
     * the key store, if it returns true, the key store must not be
     * created again, and mut be loaded. In case the key store doesn't
     * exist, the application must create a new key store.
     *
     * @param pathToKeyStore The path to key store including the file name
     * @return True/False, if true - key store exists
     */
    public boolean isKeyStoreExists(final String pathToKeyStore)
    {
        File keyStoreFile = new File(pathToKeyStore);
        if (keyStoreFile.exists())
        {
            return true;
        }
        return false;
    }

}
