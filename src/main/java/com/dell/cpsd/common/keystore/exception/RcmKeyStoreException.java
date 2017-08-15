/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.exception;

/**
 * RCM Keystore exception
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @since 1.0
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

