/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.encryption.exception;

import com.dell.cpsd.rcm.fitness.encryption.CipherManager;

/**
 * A common exception that is thrown by the {@link CipherManager} methods.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0
 */
public class CipherManagerException extends Exception
{
    public CipherManagerException(final Throwable cause)
    {
        super(cause);
    }
}
