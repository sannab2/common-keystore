/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.dell.cpsd.common.keystore.encryption.KeyStoreUtility;

import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * This is the keystore utility test class.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.2
 */
public class KeyStoreUtilityTest
{
    private KeyStoreUtility keyStoreUtility;

    @Before
    public void setup() throws Exception
    {
        keyStoreUtility = new KeyStoreUtility();
    }

    @Test
    public void create_new_keystore() throws Exception
    {
        final KeyStore keyStore = keyStoreUtility
                .createServiceKeyStore("TEST", "", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(), "pvtkey",
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray());

        Assert.assertNotNull(keyStore);

        final KeyPair keypair = new KeyStoreUtility()
                .getKeyPairFromKeyStore("TEST.p12", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(),
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray(), "pvtkey");

        Assert.assertNotNull(keypair);
    }

    @Test(expected = KeyStoreException.class)
    public void accessing_keystore_with_wrong_private_key_password_throws_exception() throws Exception
    {
        final KeyStore keyStore = keyStoreUtility
                .createServiceKeyStore("TEST", "", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(), "pvtkey",
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray());

        Assert.assertNotNull(keyStore);

        final KeyPair keypair = new KeyStoreUtility()
                .getKeyPairFromKeyStore("TEST.p12", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(),
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RqpSaYE=".toCharArray(), "pvtkey");

    }

    @Test(expected = KeyStoreException.class)
    public void accessing_keystore_with_wrong_keystore_password_throws_exception() throws Exception
    {
        final KeyStore keyStore = keyStoreUtility
                .createServiceKeyStore("TEST", "", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(), "pvtkey",
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray());

        Assert.assertNotNull(keyStore);

        final KeyPair keypair = new KeyStoreUtility()
                .getKeyPairFromKeyStore("TEST.p12", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUG0Iktao=".toCharArray(),
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray(), "pvtkey");

    }

    @Test(expected = FileNotFoundException.class)
    public void accessing_keystore_with_wrong_file_throws_exception() throws Exception
    {
        final KeyStore keyStore = keyStoreUtility
                .createServiceKeyStore("TEST", "", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(), "pvtkey",
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray());

        Assert.assertNotNull(keyStore);

        final KeyPair keypair = new KeyStoreUtility()
                .getKeyPairFromKeyStore("TEST12.p12", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(),
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray(), "pvtkey");

    }

    @Test
    public void accessing_keystore_with_wrong_alias_returns_null_keypair() throws Exception
    {
        final KeyStore keyStore = keyStoreUtility
                .createServiceKeyStore("TEST", "", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(), "pvtkey",
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray());

        Assert.assertNotNull(keyStore);

        final KeyPair keypair = new KeyStoreUtility()
                .getKeyPairFromKeyStore("TEST.p12", "otnqWF+t4Sdu+NuyC51cntzdCgsisHi9rNUaG0Iktao=".toCharArray(),
                        "H69X8ILV0St/l1nL8+gOHgjKxuZYodYbK+RVkqpSaYE=".toCharArray(), "wrong-alias");

        Assert.assertNull(keypair);

    }
}

