package com.dell.cpsd.rcm.fitness.keystore.exception;

import com.dell.cpsd.rcm.fitness.keystore.encryption.CipherManager;

/**
 * A common exception that is thrown by the {@link CipherManager} methods.
 */
public class CipherManagerException extends Exception
{
    public CipherManagerException(final Throwable cause)
    {
        super(cause);
    }
}
