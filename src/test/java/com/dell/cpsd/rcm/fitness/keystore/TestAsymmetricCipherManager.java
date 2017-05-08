package com.dell.cpsd.rcm.fitness.keystore;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionConfig;
import com.dell.cpsd.rcm.fitness.keystore.encryption.AsymmetricCipherManager;
import com.dell.cpsd.rcm.fitness.keystore.encryption.SymmetricCipherManager;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test cases for the asymmetric {@link com.dell.cpsd.rcm.fitness.keystore.encryption.CipherManager}.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {EncryptionConfig.class})
public class TestAsymmetricCipherManager
{
    @Autowired
    SymmetricCipherManager symmetricCipherManager;

    @Autowired
    AsymmetricCipherManager asymmetricCipherManager;

    @Test
    public void testRandomAsymmetricEncryption() throws Exception
    {
        String clearText = "The quick brown fox caught the slow jack rabbit.";
        byte [] cipherText = this.asymmetricCipherManager.encrypt(clearText.getBytes());
        byte [] clearTextBytes = this.asymmetricCipherManager.decrypt(cipherText);

        Assert.assertArrayEquals(clearText.getBytes(), clearTextBytes);
    }

    @Test
    public void testPublicKeyExportImport() throws Exception
    {
        String clearText = "The quick brown fox caught the slow jack rabbit.";

        // export the public key, construct a new manager around it and encrypt the clear text
        byte [] encodedPublicKey = this.asymmetricCipherManager.getPublicKeyEncoded();
        AsymmetricCipherManager asymCipherManager = new AsymmetricCipherManager(encodedPublicKey);
        byte [] cipherText = asymCipherManager.encrypt(clearText.getBytes());

        // original cipher manager has the private key for decryption
        byte [] clearTextBytes = this.asymmetricCipherManager.decrypt(cipherText);
        Assert.assertArrayEquals(clearText.getBytes(), clearTextBytes);
    }

    @Test
    public void testGenerateWithOnlyPublicKey() throws Exception
    {
        // export the public key, construct a new manager around it
        byte [] encodedPublicKey = this.asymmetricCipherManager.getPublicKeyEncoded();
        AsymmetricCipherManager asymCipherManager = new AsymmetricCipherManager(encodedPublicKey);

        // Force the new cipher manager to try and regenerate its key, which should not happen
        asymCipherManager.initialize();

        Assert.assertArrayEquals(encodedPublicKey, asymCipherManager.getPublicKeyEncoded());
    }
}
