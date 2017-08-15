/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import static com.dell.cpsd.common.keystore.i18n.RcmKeyStoreExceptionCode.ERROR1_E;

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

import com.dell.cpsd.common.keystore.config.EncryptionPropertiesConfig;

/**
 * This class provides various key store utility methods that can be
 * used across various projects. It is essential that all the services
 * use the <code>{@link KeyStoreUtility}</code> methods and not define
 * the methods in the respective projects.
 * This class can be used for creating the key stores, loading the key
 * stores, storing keys or certificates, or retrieving the keys.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since SINCE -TBD
 */
@Deprecated
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
     * <p>
     * <i>
     * Before calling this method, the calling service must check
     * if the key store already exists or not. This can be easily
     * checked by using {@link KeyStoreUtility#isKeyStoreExists(String)}
     * method which takes the file path as its parameter.
     * </i>
     * </p>
     *
     * @param serviceName      Requesting Service Name
     * @param keyStorePath     Path to the Key store (/opt/dell/rcm-fitness/services/{service-name}/conf/keystore/
     * @param keyStorePassword Password to unlock the key store
     * @param keyAlias         Alias used while storing the key, key is again retrieved using this alias
     * @param keyPassword      Password used to retrieve the key
     * @return KeyStore instance
     * @throws SignatureException       SignatureException
     * @throws NoSuchProviderException  NoSuchProviderException
     * @throws InvalidKeyException      InvalidKeyException
     * @throws KeyStoreException        KeyStoreException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws CertificateException     CertificateException
     * @throws IOException              IOException
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
            throw new KeyStoreException(ERROR1_E.getMessage(serviceName, keyStorePath, keyAlias), exception);
        }
        catch (NoSuchAlgorithmException exception)
        {
            throw new NoSuchAlgorithmException(ERROR1_E.getMessage(serviceName, keyStorePath, keyAlias), exception);
        }
        catch (CertificateException exception)
        {
            throw new CertificateException(ERROR1_E.getMessage(serviceName, keyStorePath, keyAlias), exception);
        }
        catch (IOException exception)
        {
            throw new IOException(ERROR1_E.getMessage(serviceName, keyStorePath, keyAlias), exception);
        }
    }

    /**
     * this method sets the private key entry, and certificate chain
     * entry. It is must that the keystore must be loaded first before
     * this method can be called.
     *
     * @param keyPassword Private/Secret Key password
     * @param keyAlias    Private/Secret key alias
     * @param keyStore    Keystore loaded previously
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws IOException              IOException
     * @throws CertificateException     CertificateException
     * @throws SignatureException       SignatureException
     * @throws NoSuchProviderException  NoSuchProviderException
     * @throws InvalidKeyException      InvalidKeyException
     * @throws KeyStoreException        KeyStoreException
     * @see KeyStoreUtility#createServiceKeyStore(String, String, char[], String, char[])
     * @see KeyStoreUtility#createCertificate(String, KeyPair)
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
     * This method generates the X.509 certificate. The certificate
     * info is set here, and the private key is used to sign the
     * certificate. By default the certificate validity is set for
     * 1 year from the issue date.
     *
     * @param alias   certificate alias
     * @param keyPair Key pair
     * @return X.509 Certificate
     * @throws IOException              IOException
     * @throws CertificateException     CertificateException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws SignatureException       SignatureException
     * @throws NoSuchProviderException  NoSuchProviderException
     * @throws InvalidKeyException      InvalidKeyException
     * @see KeyStoreUtility#updateKeyStore(char[], String, KeyStore)
     * @see KeyStoreUtility#signCertificate(PrivateKey, X509CertInfo)
     */
    private X509Certificate createCertificate(final String alias, final KeyPair keyPair)
            throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException,
            InvalidKeyException
    {
        final PrivateKey privateKey = keyPair.getPrivate();
        final X509CertInfo certificateInfo = new X509CertInfo();

        final Date fromDate = Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant());
        final Date toDate = Date.from(LocalDateTime.now()
                .plusYears(Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_VALIDITY_PROPERTY)))
                .atZone(ZoneId.systemDefault()).toInstant());

        final CertificateValidity certificateValidity = new CertificateValidity(fromDate, toDate);
        final BigInteger serialNumber = new BigInteger(
                Integer.parseInt(EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_SNO_BIT_SIZE_PROPERTY)),
                new SecureRandom());
        final X500Name issuerName = new X500Name("C=" + alias);
        final X500Name subject = new X500Name("C=" + alias);

        certificateInfo.set(X509CertInfo.VALIDITY, certificateValidity);
        certificateInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        certificateInfo.set(X509CertInfo.SUBJECT, subject);
        certificateInfo.set(X509CertInfo.ISSUER, issuerName);
        certificateInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        certificateInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        final AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
        certificateInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));
        return signCertificate(privateKey, certificateInfo);
    }

    /**
     * The method signs the X.509 certificate using the private key
     * of the service. The signing algorithm used is <b>MD5WithRSA</b>.
     *
     * @param privateKey      Private key
     * @param certificateInfo Certificate Info
     * @return X509Certificate Implementation
     * @throws CertificateException     CertificateException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeyException      InvalidKeyException
     * @throws NoSuchProviderException  NoSuchProviderException
     * @throws SignatureException       SignatureException
     * @throws IOException              IOException
     * @see KeyStoreUtility#createCertificate(String, KeyPair)
     */
    private X509CertImpl signCertificate(final PrivateKey privateKey, final X509CertInfo certificateInfo)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException,
            IOException
    {
        // Sign the certificate
        final X509CertImpl x509Cert = new X509CertImpl(certificateInfo);
        x509Cert.sign(privateKey, EncryptionPropertiesConfig.loadProperties().getProperty(CERTIFICATE_SIGNING_ALGORITHM_PROPERTY));
        return x509Cert;
    }

    /**
     * This method is exposed to the other services and is used to get the
     * keypair from the keystore. It requires keystore and key password to
     * access the keystore first, and then with the help of the key alias,
     * and the corresponding password the key can be accessed.
     *
     * @param pathToKeyStore   The path to keystore file
     * @param keyStorePassword The password to access keystore
     * @param keyPassword      The password to access key from the keystore
     * @param keyAlias         The alias used to access private/secret key
     * @return Key pair with private and public key, or secret key
     * @throws IOException              IOException
     * @throws KeyStoreException        KeyStoreException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws CertificateException     CertificateException
     */
    public KeyPair getKeyPairFromKeyStore(final String pathToKeyStore, final char[] keyStorePassword, final char[] keyPassword,
            final String keyAlias) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException
    {
        try
        {
            final KeyStore keyStore = loadKeyStore(pathToKeyStore, keyStorePassword);

            final Key key = generateKeyFromKeyStore(keyStore, keyAlias, keyPassword);

            if (key instanceof PrivateKey)
            {
                final Certificate certificate = keyStore.getCertificate(keyAlias);

                final PublicKey publicKey = certificate.getPublicKey();

                return new KeyPair(publicKey, (PrivateKey) key);
            }
        }
        catch (KeyStoreException exception)
        {
            throw new KeyStoreException("Error in getting a key pair from the keystore");
        }

        return null;
    }

    /**
     * This method loads the keystore and requires keystore location and
     * the password to access the keystore. The method should not me called
     * directly, as obtaining the keystore serves no purpose, the application
     * only needs the private and public key pair.
     *
     * @param pathToKeyStore   This is the path to the keystore along with
     *                         the keystore file name.
     * @param keyStorePassword The password required to
     * @return Keystore
     * @throws IOException              IOException
     * @throws KeyStoreException        KeyStoreException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws CertificateException     CertificateException
     * @see KeyStoreUtility#getKeyPairFromKeyStore(String, char[], char[], String)
     */
    private KeyStore loadKeyStore(final String pathToKeyStore, final char[] keyStorePassword)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException
    {
        try (InputStream fileInputStream = new FileInputStream(pathToKeyStore))
        {
            final KeyStore keyStore = KeyStore.getInstance(EncryptionPropertiesConfig.loadProperties().getProperty(KEYSTORE_TYPE_PROPERTY));
            keyStore.load(fileInputStream, keyStorePassword);

            return keyStore;
        }
        catch (FileNotFoundException exception)
        {
            throw new FileNotFoundException(exception.getMessage());
        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException exception)
        {
            throw new KeyStoreException(exception.getMessage());
        }
    }

    /**
     * This method provides the public key from the certificate that is
     * loaded from the keystore. This method does exactly the same as
     * {@link KeyStoreUtility#getKeyPairFromKeyStore(String, char[], char[], String)},
     * only difference is this one method returns the keypair containing both
     * private and public key and another method returns only the public key.
     *
     * @param pathToKeyStore   The path to keystore file
     * @param keyStorePassword The password to access keystore
     * @param keyPassword      The password to access key from the keystore
     * @param keyAlias         The alias used to access private/secret key
     * @return Public key
     * @throws IOException              IOException
     * @throws KeyStoreException        KeyStoreException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws CertificateException     CertificateException
     */
    public PublicKey getPublicKey(final String pathToKeyStore, final char[] keyStorePassword, final char[] keyPassword,
            final String keyAlias) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException
    {
        try
        {
            final KeyStore keyStore = loadKeyStore(pathToKeyStore, keyStorePassword);

            final Key key = generateKeyFromKeyStore(keyStore, keyAlias, keyPassword);

            if (key instanceof PrivateKey)
            {
                final Certificate certificate = keyStore.getCertificate(keyAlias);
                return certificate.getPublicKey();
            }
        }
        catch (KeyStoreException exception)
        {
            throw new KeyStoreException("Error in obtaining the public key from the key store");
        }

        return null;
    }

    /**
     * This method returns the key instance and mut be called internally.
     *
     * @param keyStore    Keystore
     * @param keyAlias    Private/Secret key alias
     * @param keyPassword Private/Secret key password
     * @return Key instance
     */
    private Key generateKeyFromKeyStore(final KeyStore keyStore, final String keyAlias, final char[] keyPassword) throws KeyStoreException
    {
        try
        {
            return keyStore.getKey(keyAlias, keyPassword);
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception)
        {
            throw new KeyStoreException("Error in generating the key from the keystore.");
        }
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
        final File keyStoreFile = new File(pathToKeyStore);
        return keyStoreFile.exists();
    }

}
