/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore;

import com.dell.cpsd.rcm.fitness.keystore.encryption.PasswordEncryptionUtility;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


/**
 * TODO: Document usage.
 * <p>
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 * </p>
 *
 * @since Vision 1.0.0
 */
public class PasswordEncryptionUtilityTest
{
    private PasswordEncryptionUtility passwordEncryptionUtility;

    @Before
    public void setup()
    {
        passwordEncryptionUtility = new PasswordEncryptionUtility();
    }

    @Test
    public void encrypted_password_not_null() throws Exception
    {
        final String encryptedPassword_1 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-keystore");
        final String encryptedPassword_2 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-keystore");

        final String encryptedPassword_3 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-private-key");
        final String encryptedPassword_4 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-private-key");

        Assert.assertNotNull(encryptedPassword_1);
        Assert.assertNotNull(encryptedPassword_2);
        Assert.assertNotNull(encryptedPassword_3);
        Assert.assertNotNull(encryptedPassword_4);
    }

    @Test(expected = EncryptionOperationNotPossibleException.class)
    public void encrypted_decrypted_passwords_using_different_password_throws_exception() throws Exception
    {
        final String encryptedPassword_1 = passwordEncryptionUtility.encryptPassword("symphony-hal1".toCharArray(), "hal-orchestrator-keystore");

        passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encryption_without_supplying_pbe_password_throws_exception() throws Exception
    {
        passwordEncryptionUtility.encryptPassword("".toCharArray(), "hal-orchestrator-keystore");
    }

    @Test(expected = IllegalArgumentException.class)
    public void encryption_using_null_pbe_password_throws_exception() throws Exception
    {
        passwordEncryptionUtility.encryptPassword(null, "hal-orchestrator-keystore");
    }

    @Test
    public void encrypted_passwords_not_same_new_every_time() throws Exception
    {
        final String encryptedPassword_1 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-keystore");
        final String encryptedPassword_2 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-keystore");

        final String encryptedPassword_3 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-private-key");
        final String encryptedPassword_4 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-private-key");

        Assert.assertNotEquals(encryptedPassword_1, encryptedPassword_2);
        Assert.assertNotEquals(encryptedPassword_3, encryptedPassword_4);
    }

    @Test
    public void decrypted_password_not_null() throws Exception
    {
        final String encryptedPassword_1 = "6Z5VSgEfL04eYYMRJO5FwDi/Q+gDKkSdBsjpVC8KEMVrDj8tfTjdEg==";
        final String encryptedPassword_2 = "2+10NCOy98jJ8O+VhFk984NaIV81/JK3qzMEeYgg+T1bGZFtCV8gJQ==";

        final String encryptedPassword_3 = "2RyXs1iovD136g57qvFXr1Ceto6G7ySF9cQkR7IWGGk0iA1kWJ7xSw==";
        final String encryptedPassword_4 = "wLaawHaug3ok2bSr71Ul3mYTpHur4Tb27DrSEp+XRUwnXq22T7YE3Q==";

        final char[] decryptedPassword_1 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_1);
        final char[] decryptedPassword_2 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_2);

        final char[] decryptedPassword_3 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_3);
        final char[] decryptedPassword_4 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_4);

        Assert.assertNotNull(decryptedPassword_1);
        Assert.assertNotNull(decryptedPassword_2);
        Assert.assertNotNull(decryptedPassword_3);
        Assert.assertNotNull(decryptedPassword_4);
    }

    @Test
    public void plain_text_and_decrypted_password_are_same() throws Exception
    {
        final String encryptedPassword_1 = "6Z5VSgEfL04eYYMRJO5FwDi/Q+gDKkSdBsjpVC8KEMVrDj8tfTjdEg==";
        final String encryptedPassword_2 = "2+10NCOy98jJ8O+VhFk984NaIV81/JK3qzMEeYgg+T1bGZFtCV8gJQ==";

        final String encryptedPassword_3 = "2RyXs1iovD136g57qvFXr1Ceto6G7ySF9cQkR7IWGGk0iA1kWJ7xSw==";
        final String encryptedPassword_4 = "wLaawHaug3ok2bSr71Ul3mYTpHur4Tb27DrSEp+XRUwnXq22T7YE3Q==";

        final char[] decryptedPassword_1 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_1);
        final char[] decryptedPassword_2 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_2);

        final char[] decryptedPassword_3 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_3);
        final char[] decryptedPassword_4 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_4);

        Assert.assertArrayEquals(decryptedPassword_1, decryptedPassword_2);
        Assert.assertArrayEquals("hal-orchestrator-keystore".toCharArray(), decryptedPassword_1);
        Assert.assertArrayEquals("hal-orchestrator-keystore".toCharArray(), decryptedPassword_2);

        Assert.assertArrayEquals(decryptedPassword_3, decryptedPassword_4);
        Assert.assertArrayEquals("hal-orchestrator-private-key".toCharArray(), decryptedPassword_3);
        Assert.assertArrayEquals("hal-orchestrator-private-key".toCharArray(), decryptedPassword_4);
    }

    @Test
    public void decrypted_passwords_from_encrypted_passwords_same() throws Exception
    {
        final String encryptedPassword_1 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-keystore");
        final String encryptedPassword_2 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-keystore");

        final String encryptedPassword_3 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-private-key");
        final String encryptedPassword_4 = passwordEncryptionUtility.encryptPassword("symphony-hal".toCharArray(), "hal-orchestrator-private-key");

        final char[] decryptedPassword_1 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_1);
        final char[] decryptedPassword_2 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_2);

        final char[] decryptedPassword_3 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_3);
        final char[] decryptedPassword_4 = passwordEncryptionUtility.decryptPassword("symphony-hal".toCharArray(), encryptedPassword_4);

        Assert.assertArrayEquals(decryptedPassword_1, decryptedPassword_2);
        Assert.assertArrayEquals("hal-orchestrator-keystore".toCharArray(), decryptedPassword_1);
        Assert.assertArrayEquals("hal-orchestrator-keystore".toCharArray(), decryptedPassword_2);

        Assert.assertArrayEquals(decryptedPassword_3, decryptedPassword_4);
        Assert.assertArrayEquals("hal-orchestrator-private-key".toCharArray(), decryptedPassword_3);
        Assert.assertArrayEquals("hal-orchestrator-private-key".toCharArray(), decryptedPassword_4);
    }
}

