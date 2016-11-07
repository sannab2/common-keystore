/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore.exception;

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
public class RcmKeyStoreException extends Exception
{

    /**
     * CredentialServiceException constructor.
     *
     * @param message The exception message.
     * @since SINCE-TBD
     */
    public RcmKeyStoreException(String message)
    {
        super(message);
    }

    /**
     * CredentialServiceException constructor.
     *
     * @param cause The cause of the exception.
     * @since SINCE-TBD
     */
    public RcmKeyStoreException(Throwable cause)
    {
        super(cause);
    }

    /**
     * CredentialServiceException constructor.
     *
     * @param message The exception message.
     * @param cause   The cause of the exception.
     * @since SINCE-TBD
     */
    public RcmKeyStoreException(String message, Throwable cause)
    {
        super(message, cause);
    }
}

