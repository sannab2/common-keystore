/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Common methods used by @{@link CipherManager} implementations.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0
 */
public abstract class AbstractCipherManager implements CipherManager
{
    private static final int    SEED_LENGTH           = 32;

    private SecureRandom random = new SecureRandom();

    /**
     * Overwrite a byte array with all zeros
     *
     * @param array Byte Array
     */
    public void clear(byte[] array)
    {
        byte zeroByte = 0;
        Arrays.fill(array, zeroByte);
    }

    /**
     * Update the seed information for the internal, random object.
     */
    public void reseed()
    {
        this.random.setSeed(this.random.generateSeed(SEED_LENGTH));
    }

    protected SecureRandom getRandom()
    {
        return random;
    }
}
