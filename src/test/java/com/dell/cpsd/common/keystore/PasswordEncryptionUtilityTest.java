/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore;

import org.junit.Before;
import org.junit.Test;

import com.dell.cpsd.common.keystore.encryption.PasswordEncryptionUtility;

import javax.crypto.BadPaddingException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

/**
 * This is the unit test class for {@link PasswordEncryptionUtility}.
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.1
 * @since 1.0
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
    public void secret_key_hex_not_null() throws Exception
    {
        final String secretKeyHex = passwordEncryptionUtility.getSecretKeyHex();
        assertNotNull(secretKeyHex);
    }

    @Test
    public void no_two_secret_keys_hex_are_same() throws Exception
    {
        final String secretKeyHex_1 = passwordEncryptionUtility.getSecretKeyHex();
        final String secretKeyHex_2 = passwordEncryptionUtility.getSecretKeyHex();

        assertNotEquals(secretKeyHex_1, secretKeyHex_2);
    }

    @Test
    public void encrypted_password_not_null() throws Exception
    {
        final String secretKeyHex = passwordEncryptionUtility.getSecretKeyHex();
        final String plainTextPassword = "hello-world";

        final String encryptedPassword = passwordEncryptionUtility.encryptText(plainTextPassword, secretKeyHex);

        assertNotNull(encryptedPassword);
    }

    @Test
    public void decrypted_password_not_null() throws Exception
    {
        final String secretKeyHex = passwordEncryptionUtility.getSecretKeyHex();
        final String plainTextPassword = "hello-world";

        final String encryptedPassword = passwordEncryptionUtility.encryptText(plainTextPassword, secretKeyHex);

        final String decryptedPassword = passwordEncryptionUtility.decryptText(encryptedPassword, secretKeyHex);

        assertNotNull(decryptedPassword);
    }

    @Test(expected = BadPaddingException.class)
    public void decryption_with_different_secret_key_throws_exception() throws Exception
    {
        final String secretKeyHex = passwordEncryptionUtility.getSecretKeyHex();
        final String plainTextPassword = "hello-world";

        final String encryptedPassword = passwordEncryptionUtility.encryptText(plainTextPassword, secretKeyHex);

        final String differentSecretKeyHex = passwordEncryptionUtility.getSecretKeyHex();

        passwordEncryptionUtility.decryptText(encryptedPassword, differentSecretKeyHex);
    }

    @Test
    public void plain_text_and_decrypted_text_are_same() throws Exception
    {
        final String secretKeyHex = passwordEncryptionUtility.getSecretKeyHex();
        final String plainTextPassword = "hello-world";

        final String encryptedPassword = passwordEncryptionUtility.encryptText(plainTextPassword, secretKeyHex);

        final String decryptedPassword = passwordEncryptionUtility.decryptText(encryptedPassword, secretKeyHex);

        assertEquals(plainTextPassword, decryptedPassword);
    }

    @Test
    public void example_for_hal_orchestrator() throws Exception
    {
        final String secretKeyHexForHal = passwordEncryptionUtility.getSecretKeyHex();

        final String halOrchestratorKeyStorePassword = "hal-orchestrator-keystore";
        final String halOrchestratorPrivateKeyPassword = "hal-orchestrator-private-key";

        final String encryptedKeyStorePassword = passwordEncryptionUtility.encryptText(halOrchestratorKeyStorePassword, secretKeyHexForHal);
        final String encryptedPrivateKeyPassword = passwordEncryptionUtility
                .encryptText(halOrchestratorPrivateKeyPassword, secretKeyHexForHal);

        final String decryptedKeyStorePassword = passwordEncryptionUtility.decryptText(encryptedKeyStorePassword, secretKeyHexForHal);
        final String decryptedPrivateKeyPassword = passwordEncryptionUtility.decryptText(encryptedPrivateKeyPassword, secretKeyHexForHal);

        assertEquals(halOrchestratorKeyStorePassword, decryptedKeyStorePassword);
        assertEquals(halOrchestratorPrivateKeyPassword, decryptedPrivateKeyPassword);

        System.out.println("Hal Orchestrator Key Store password: " + halOrchestratorKeyStorePassword);
        System.out.println("Hal Orchestrator Private Key password: " + halOrchestratorPrivateKeyPassword);
        System.out.println("Secret Key Hex For HAL <GOES IN PROPERTIES FILE>: " + secretKeyHexForHal);
        System.out.println("Hal Orchestrator Keystore Encrypted Password <GOES IN PROPERTIES FILE>: " + encryptedKeyStorePassword);
        System.out.println("Hal Orchestrator Private Key Encrypted Password <GOES IN PROPERTIES FILE>: " + encryptedPrivateKeyPassword);
        System.out.println("Hal Orchestrator Keystore Decrypted Password: " + decryptedKeyStorePassword);
        System.out.println("Hal Orchestrator Private Key Decrypted Password: " + decryptedPrivateKeyPassword);

    }

    @Test
    public void example_for_credential_service() throws Exception
    {
        final String secretKeyHexForCredential = passwordEncryptionUtility.getSecretKeyHex();

        final String credentialServiceKeyStorePassword = "credential-keystore";
        final String credentialServicePrivateKeyPassword = "credential-private-key";

        final String encryptedKeyStorePassword = passwordEncryptionUtility
                .encryptText(credentialServiceKeyStorePassword, secretKeyHexForCredential);
        final String encryptedPrivateKeyPassword = passwordEncryptionUtility
                .encryptText(credentialServicePrivateKeyPassword, secretKeyHexForCredential);

        final String decryptedKeyStorePassword = passwordEncryptionUtility
                .decryptText(encryptedKeyStorePassword, secretKeyHexForCredential);
        final String decryptedPrivateKeyPassword = passwordEncryptionUtility
                .decryptText(encryptedPrivateKeyPassword, secretKeyHexForCredential);

        assertEquals(credentialServiceKeyStorePassword, decryptedKeyStorePassword);
        assertEquals(credentialServicePrivateKeyPassword, decryptedPrivateKeyPassword);

        System.out.println("Credential Service Key Store password: " + credentialServiceKeyStorePassword);
        System.out.println("Credential Service Private Key password: " + credentialServicePrivateKeyPassword);
        System.out.println("Secret Key Hex For Credential <GOES IN PROPERTIES FILE>: " + secretKeyHexForCredential);
        System.out.println("Credential Service Keystore Encrypted Password <GOES IN PROPERTIES FILE>: " + encryptedKeyStorePassword);
        System.out.println("Credential Service Private Key Encrypted Password <GOES IN PROPERTIES FILE>: " + encryptedPrivateKeyPassword);
        System.out.println("Credential Service Keystore Decrypted Password: " + decryptedKeyStorePassword);
        System.out.println("Credential Service Private Key Decrypted Password: " + decryptedPrivateKeyPassword);

    }
}

