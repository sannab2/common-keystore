/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.dell.cpsd.common.keystore.encryption.exception.CipherManagerException;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * The {@link AsymmetricCipherManager} generates a new RSA key pair. The private
 * key is encrypted with a {@link SymmetricCipherManager} to ensure the private
 * key cannot be easily found in RAM via a memory dump.
 * <p>
 * We are using a lower value RSA key pair (2048-bit) as the final code will re-initialize
 * all of the encryption data every ~5 minutes. A 2048-bit asymmetric key will be good
 * enough to protect the data for that length of time.
 * <p>
 * TODO Every ~5 minutes, generate a new symmetric key and asymmetric key pair
 * <p>
 * TODO Allow overriding the default key size to a larger value. Must be set system wide.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0
 */
public class AsymmetricCipherManager extends AbstractCipherManager
{
    private static final int    ASYMMETRIC_LENGTH = 2048; // 2048-bit minimum
    private static final String ASYMMETRIC_TYPE   = "RSA";

    private PublicKey publicKey;
    private byte[]    encryptedPrivateKey;
    private SymmetricCipherManager symmetricCipherManager;

    public AsymmetricCipherManager() throws CipherManagerException
    {
    }

    /**
     * Construct a new cipher manager with just the encoded public key. Convert the encoded
     * public key back to an RSA-based {@link PublicKey}. Ensure the private key is left as null.
     *
     * @param publicKeyEncoded A public key in an encoded format
     * @throws CipherManagerException CipherManagerException
     */
    public AsymmetricCipherManager(byte[] publicKeyEncoded) throws CipherManagerException
    {
        try
        {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_TYPE);
            this.publicKey = keyFactory.generatePublic(keySpec);
            this.encryptedPrivateKey = null;
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new CipherManagerException(e);
        }
    }

    /**
     * Generate a random symmetric key (AES 128-bit).
     * Generate a random asymmetric key pair (RSA 2048-bit)
     *
     * @throws CipherManagerException CipherManagerException
     */
    public void initialize() throws CipherManagerException
    {
        if (null != this.publicKey && null == this.encryptedPrivateKey)
        {
            return;
        }

        synchronized (this)
        {
            this.symmetricCipherManager.initialize();
            reseed();
            generateAsymmetricKeyPair();
        }
    }

    /**
     * Encrypt the clearText using the RSA publicKey.
     *
     * @param clearText Byte array to be encrypted
     * @return A portable, encrypted, Base64-encoded byte array
     * @throws CipherManagerException CipherManagerException
     */
    @Override
    public byte[] encrypt(final byte[] clearText) throws CipherManagerException
    {
        synchronized (this)
        {
            try
            {
                Cipher cipher = Cipher.getInstance(ASYMMETRIC_TYPE);
                cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
                byte[] cipherText = cipher.doFinal(clearText);
                byte[] encodedCipherText = Base64.getEncoder().encode(cipherText);
                clear(cipherText);
                return encodedCipherText;
            }
            catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e)
            {
                throw new CipherManagerException(e);
            }
        }
    }

    /**
     * Decrypt the cipherText using the stored, protected private key.
     * Use the private key to decrypt the encryptedPrivateKey. Convert back
     * to a PrivateKey (RSA) and decrypt the cipherText.
     *
     * @param cipherText A portable, encrypted, Base64-encoded byte array
     * @return Decrypted byte array
     * @throws CipherManagerException CipherManagerException
     */
    @Override
    public byte[] decrypt(final byte[] cipherText) throws CipherManagerException
    {
        synchronized (this)
        {
            try
            {
                byte[] key = this.getSymmetricCipherManager().decrypt(this.encryptedPrivateKey);
                PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(key);
                clear(key); // remove the decrypted key from memory
                KeyFactory kf = KeyFactory.getInstance(ASYMMETRIC_TYPE);
                PrivateKey privateKey = kf.generatePrivate(ks);
                Cipher cipher = Cipher.getInstance(ASYMMETRIC_TYPE);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decodedCipherText = Base64.getDecoder().decode(cipherText);
                byte[] clearText = cipher.doFinal(decodedCipherText);
                clear(decodedCipherText);
                return clearText;
            }
            catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException e)
            {
                throw new CipherManagerException(e);
            }
        }
    }

    /**
     * Return the public key in an encoded format.
     *
     * @return A public key in an encoded format
     */
    public byte[] getPublicKeyEncoded()
    {
        synchronized (this)
        {
            return this.publicKey.getEncoded();
        }
    }


    public String getPublicKeyEncodedBase64()
    {
       return  new String(Base64.getEncoder().encode(getPublicKeyEncoded()));
    }

    /**
     * Generate a new 2048-bit asymmetric key pair
     * Protect the private key by encrypting it with a symmetric key
     */
    private void generateAsymmetricKeyPair() throws CipherManagerException
    {
        // If the public key has been set but not the private key, exit out
        if (null != this.publicKey && null == this.encryptedPrivateKey)
        {
            return;
        }

        synchronized (this)
        {
            try
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(ASYMMETRIC_TYPE);
                kpg.initialize(ASYMMETRIC_LENGTH, getRandom());
                KeyPair keypair = kpg.generateKeyPair();
                this.publicKey = keypair.getPublic();

                byte[] privateKeyBytes = keypair.getPrivate().getEncoded();
                this.encryptedPrivateKey = this.getSymmetricCipherManager().encrypt(privateKeyBytes);
                clear(privateKeyBytes); // remove the private key from memory
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new CipherManagerException(e);
            }
        }
    }

    private SymmetricCipherManager getSymmetricCipherManager()
    {
        return symmetricCipherManager;
    }

    public void setSymmetricCipherManager(final SymmetricCipherManager symmetricCipherManager)
    {
        this.symmetricCipherManager = symmetricCipherManager;
    }
}
