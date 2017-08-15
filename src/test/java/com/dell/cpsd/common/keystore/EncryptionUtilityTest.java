/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore;

import org.junit.Assert;
import org.junit.Test;

import com.dell.cpsd.common.keystore.encryption.EncryptionUtility;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * This is the test class for EncryptionUtility class.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * <p/>
 *
 * @version 1.0
 * @since SINCE-TBD
 */
public class EncryptionUtilityTest
{

    @Test(expected = NoSuchAlgorithmException.class)
    public void no_such_algorithm_exception() throws Exception
    {
        EncryptionUtility.obtainPublicKey("AES");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void invalid_key_specification_exception() throws Exception
    {
        PublicKey publicKey = EncryptionUtility.obtainPublicKey(EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        String publicKeyString = EncryptionUtility.generatePublicKeyString(publicKey);

        EncryptionUtility.derivePublicKeyFromString(publicKeyString, "DSA");
    }

    @Test
    public void compare_PublicKey_With_DerivedPublicKey() throws Exception
    {
        PublicKey publicKey = EncryptionUtility.obtainPublicKey(EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        String publicKeyString = EncryptionUtility.generatePublicKeyString(publicKey);

        PublicKey derivedPublicKey = EncryptionUtility
                .derivePublicKeyFromString(publicKeyString, EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        Assert.assertEquals(derivedPublicKey, publicKey);
    }

    @Test
    public void compare_CipherText_With_PlainText_NotSame() throws Exception
    {
        PublicKey publicKey = EncryptionUtility.obtainPublicKey(EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        String plainText = "unencryptedPassword";

        String cipherText = EncryptionUtility.cipherText(publicKey, plainText, EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        Assert.assertNotEquals(plainText, cipherText);
        Assert.assertNotSame(cipherText, plainText);
    }

    @Test
    public void compare_CipherText_With_DecipherText_Same() throws Exception
    {
        KeyPair keyPair = EncryptionUtility.obtainKeyPair(EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        String plainText = "unencryptedPassword";

        String cipherText = EncryptionUtility.cipherText(keyPair.getPublic(), plainText, EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        String decipherText = EncryptionUtility
                .decipherText(keyPair.getPrivate(), cipherText, EncryptionPropertiesTest.ENCRYPTION_ALGORITHM);

        Assert.assertEquals(decipherText, plainText);
    }
}
