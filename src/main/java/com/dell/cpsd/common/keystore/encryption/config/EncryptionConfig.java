/**
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.encryption.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import com.dell.cpsd.common.keystore.encryption.AsymmetricCipherManager;
import com.dell.cpsd.common.keystore.encryption.CipherManager;
import com.dell.cpsd.common.keystore.encryption.SymmetricCipherManager;
import com.dell.cpsd.common.keystore.encryption.exception.CipherManagerException;

/**
 * A Spring configuration class that can be used directly to auto wire
 * the encryption {@link CipherManager} implementations
 * into an service or PAQX.
 * <p>
 * Copyright &copy; 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0
 */
@Configuration
@EnableAsync
@EnableScheduling
public class EncryptionConfig
{
    private SymmetricCipherManager  symmetricCipherManager;
    private AsymmetricCipherManager asymmetricCipherManager;

    @Bean
    public SymmetricCipherManager getSymmetricCipherManager()
    {
        if (null == this.symmetricCipherManager)
        {
            this.symmetricCipherManager = new SymmetricCipherManager();
        }

        return this.symmetricCipherManager;
    }

    @Bean
    public AsymmetricCipherManager getAsymmetricCipherManager() throws CipherManagerException
    {
        if (null == this.asymmetricCipherManager)
        {
            this.asymmetricCipherManager = new AsymmetricCipherManager();
            this.asymmetricCipherManager.setSymmetricCipherManager(getSymmetricCipherManager());
            this.asymmetricCipherManager.initialize();
        }

        return this.asymmetricCipherManager;
    }

    @Scheduled(fixedRate = 5000)
    public void reseed() throws CipherManagerException
    {
        getSymmetricCipherManager().reseed();
        getAsymmetricCipherManager().reseed();
    }
}
