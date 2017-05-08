package com.dell.cpsd.rcm.fitness.encryption;

import com.dell.cpsd.rcm.fitness.encryption.exception.CipherManagerException;

/**
 * {@link CipherManager} defines methods to encrypt and decrypt data
 * regardless of type of encryption.
 */
public interface CipherManager
{
    byte[] encrypt(byte[] clearText) throws CipherManagerException;

    byte[] decrypt(byte[] cipherText) throws CipherManagerException;
}
