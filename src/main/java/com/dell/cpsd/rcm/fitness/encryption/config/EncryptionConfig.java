package com.dell.cpsd.rcm.fitness.encryption.config;

import com.dell.cpsd.rcm.fitness.encryption.AsymmetricCipherManager;
import com.dell.cpsd.rcm.fitness.encryption.CipherManager;
import com.dell.cpsd.rcm.fitness.encryption.exception.CipherManagerException;
import com.dell.cpsd.rcm.fitness.encryption.SymmetricCipherManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * A Spring configuration class that can be used directly to auto wire
 * the encryption {@link CipherManager} implementations
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
