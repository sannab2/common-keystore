package com.dell.cpsd.rcm.fitness.keystore;

import com.dell.cpsd.rcm.fitness.keystore.config.EncryptionConfig;
import com.dell.cpsd.rcm.fitness.keystore.exception.CipherManagerException;
import com.dell.cpsd.rcm.fitness.keystore.encryption.SymmetricCipherManager;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test cases for the symmetric {@link com.dell.cpsd.rcm.fitness.keystore.encryption.CipherManager}.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {EncryptionConfig.class})
public class TestSymmetricCipherManager
{
    @Autowired
    SymmetricCipherManager symmetricCipherManager;

    @Test
    public void testSymmetricCipherManager() throws CipherManagerException
    {
        String clearText = "There is a tree in the house!";
        byte [] cipherText = this.symmetricCipherManager.encrypt(clearText.getBytes());
        byte [] clearTextBytes = this.symmetricCipherManager.decrypt(cipherText);

        Assert.assertArrayEquals(clearText.getBytes(), clearTextBytes);
    }

    @Test(expected = CipherManagerException.class)
    public void testDecryptionFailure() throws CipherManagerException
    {
        String clearText = "There is a tree in the house!";
        byte [] cipherText = this.symmetricCipherManager.encrypt(clearText.getBytes());

        // pass in random data to be decrypted, which shall fail
        this.symmetricCipherManager.decrypt("random junk".getBytes());
    }
}
