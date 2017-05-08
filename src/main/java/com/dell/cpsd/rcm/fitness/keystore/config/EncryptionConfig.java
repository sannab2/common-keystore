package com.dell.cpsd.rcm.fitness.keystore.config;

import com.dell.cpsd.rcm.fitness.keystore.encryption.AsymmetricCipherManager;
import com.dell.cpsd.rcm.fitness.keystore.exception.CipherManagerException;
import com.dell.cpsd.rcm.fitness.keystore.encryption.SymmetricCipherManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * A Spring configuration class that can be used directly to auto wire
 * the encryption {@link com.dell.cpsd.rcm.fitness.keystore.encryption.CipherManager} implementations
 * into an service or PAQX.
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
