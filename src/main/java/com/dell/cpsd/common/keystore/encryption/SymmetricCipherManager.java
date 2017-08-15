/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */
package com.dell.cpsd.common.keystore.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.dell.cpsd.common.keystore.encryption.exception.CipherManagerException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * The {@link SymmetricCipherManager} generates a new 128-bit RSA key that is
 * used for both encryption and decryption.
 * <p>
 * TODO Allow overriding the default key size and salt-length to a larger value. Must be set system wide.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0
 */
public class SymmetricCipherManager extends AbstractCipherManager
{
    private static final int    SALT_LENGTH           = 128; // 128 character minimum
    private static final int    SYMMETRIC_KEY_LENGTH  = 16; // 16-bytes, 128-bit minimum
    private static final String SYMMETRIC_TYPE        = "AES";
    private static final String SYMMETRIC_CIPHER_TYPE = "AES/CBC/PKCS5Padding";

    private SecretKeySpec symmetricEncryptionKey;

    public SymmetricCipherManager()
    {
        initialize();
    }

    public void initialize()
    {
        synchronized (this)
        {
            reseed();
            generateSymmetricKey();
        }
    }

    /**
     * Encrypt the privateKeyBytes array using the current symmetric key. Append a random salt
     * to the key material before encrypting.
     *
     * @param clearText Byte array to be encrypted
     * @return A portable, encrypted, Base64-encoded byte array
     */
    @Override
    public byte[] encrypt(final byte[] clearText) throws CipherManagerException
    {
        try
        {
            Cipher cipher = initializeCipher(Cipher.ENCRYPT_MODE);
            byte[] salt = generateSalt(SALT_LENGTH);

            byte value[] = new byte[salt.length + clearText.length];
            System.arraycopy(salt, 0, value, 0, salt.length);
            System.arraycopy(clearText, 0, value, salt.length, clearText.length);
            byte[] cipherText = cipher.doFinal(value);
            clear(salt); // remove the salt text from memory

            return cipherText;
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new CipherManagerException(e);
        }
    }

    /**
     * Decrypt the provided key. Remove the salt that was appended before returning the clear text.
     *
     * NOTE: The caller is responsible to clear the resulting clearText. They can use the clear method
     * on the {@link SymmetricCipherManager}.
     *
     * @param cipherText A portable, encrypted, Base64-encoded byte array
     * @return Decrypted byte array
     * @throws CipherManagerException CipherManagerException
     */
    @Override
    public byte[] decrypt(final byte[] cipherText) throws CipherManagerException
    {
        try
        {
            Cipher cipher = initializeCipher(Cipher.DECRYPT_MODE);
            byte[] decrypted = cipher.doFinal(cipherText);
            byte[] clearText = new byte[decrypted.length - SALT_LENGTH];
            clear(clearText); // zero the final clear text area
            System.arraycopy(decrypted, SALT_LENGTH, clearText, 0, decrypted.length - SALT_LENGTH);

            clear(decrypted); // remove the extra copy of the decrypted text with salt

            return clearText;
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new CipherManagerException(e);
        }
    }

    /**
     * Initialize the cipher suite that is used for both encryption and decryption.
     *
     * @param mode Cipher.ENCRYPT_MODE | Cipher.DECRYPT_MODE
     * @return Cipher suite used for both encryption and decryption
     */
    private Cipher initializeCipher(int mode) throws CipherManagerException
    {
        try
        {
            byte[] iv = new byte[SYMMETRIC_KEY_LENGTH];
            clear(iv); // zero out the iv used to encrypt
            IvParameterSpec zeroIv = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_TYPE);
            cipher.init(mode, this.symmetricEncryptionKey, zeroIv);

            return cipher;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            throw new CipherManagerException(e);
        }
    }

    /**
     * Generate a new 128-bit (16-bytes) symmetric key
     */
    private void generateSymmetricKey()
    {
        byte[] key = new byte[SYMMETRIC_KEY_LENGTH];
        getRandom().nextBytes(key);
        this.symmetricEncryptionKey = new SecretKeySpec(key, SYMMETRIC_TYPE);
        clear(key); // clear the symmetric key copy from memory
    }

    /**
     * Generate a random salt to be used during symmetric encryption
     *
     * @param saltLength  Length of Random salt
     * @return Random salt used during symmetric encryption
     */
    private byte[] generateSalt(final int saltLength)
    {
        byte[] salt = new byte[saltLength];
        getRandom().nextBytes(salt);
        return salt;
    }
}
