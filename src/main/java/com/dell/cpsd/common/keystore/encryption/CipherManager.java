/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption;

import com.dell.cpsd.common.keystore.encryption.exception.CipherManagerException;

/**
 * {@link CipherManager} defines methods to encrypt and decrypt data
 * regardless of type of encryption.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @since 1.0
 */
public interface CipherManager
{
    byte[] encrypt(byte[] clearText) throws CipherManagerException;

    byte[] decrypt(byte[] cipherText) throws CipherManagerException;
}
