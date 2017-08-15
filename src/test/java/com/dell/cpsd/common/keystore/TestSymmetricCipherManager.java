/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.dell.cpsd.common.keystore.encryption.CipherManager;
import com.dell.cpsd.common.keystore.encryption.SymmetricCipherManager;
import com.dell.cpsd.common.keystore.encryption.config.EncryptionConfig;
import com.dell.cpsd.common.keystore.encryption.exception.CipherManagerException;

/**
 * Test cases for the symmetric {@link CipherManager}.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0l
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
