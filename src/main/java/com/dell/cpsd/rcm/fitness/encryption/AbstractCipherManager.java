package com.dell.cpsd.rcm.fitness.encryption;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Common methods used by @{@link CipherManager} implementations.
 */
public abstract class AbstractCipherManager implements CipherManager
{
    private static final int    SEED_LENGTH           = 32;

    private SecureRandom random = new SecureRandom();

    /**
     * Overwrite a byte array with all zeros
     *
     * @param array
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
