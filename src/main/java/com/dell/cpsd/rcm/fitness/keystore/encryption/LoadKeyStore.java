package com.dell.cpsd.rcm.fitness.keystore.encryption;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

import static com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig.PROPERTY_KEYSTORE_TYPE;
import static com.dell.cpsd.rcm.fitness.keystore.config.EncryptionPropertiesConfig.loadProperties;

//TODO
public class LoadKeyStore
{
    //TODO
    public static KeyPair getKeyPair(final String pathToKeyStore, final char[] keyStorePassword, final char[] keyPassword,
            final String keyStoreAlias)
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
            //TODO
            // Don't handle the exceptions
        }

        return null;
    }

    //TODO
    public static PublicKey getPublicKey(final String pathToKeyStore, final char[] keyStorePassword, final char[] keyPassword,
            final String keyStoreAlias)
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
            //TODO
            // Don't handle the exceptions
        }

        return null;
    }

    //TODO
    private static KeyStore loadKeyStore(final String pathToKeyStore, final char[] keyStorePassword)
    {
        try (InputStream fileInputStream = new FileInputStream(pathToKeyStore))
        {
            Properties properties = loadProperties();
            KeyStore keyStore = KeyStore.getInstance(properties.getProperty(PROPERTY_KEYSTORE_TYPE));
            keyStore.load(fileInputStream, keyStorePassword);

            //Key key = keyStore.getKey(keyStoreAlias, keyPassword);

            return keyStore;
        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException exception)
        {
            //TODO
            // Don't handle the exceptions
        }

        return null;
    }

    //TODO
    private static Key generateKeyFromKeyStore(final KeyStore keyStore, final String keyStoreAlias, final char[] keyPassword)
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

}
