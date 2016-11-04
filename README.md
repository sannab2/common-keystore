## RCM Fitness Common KeyStore

### Description

<p>
The rcm-fitness-common-keystore project is responsible for generating the Key Stores which can be used for storing private keys and certificate chains.
Other than the key stores functionality, this project also provides the utility class for encrypting the plain text information using
the public key of the other services and decrypting it using its private key.
</p>

<p>
Each Service needs to have its own key store than can hold both public and private keys. The project utilizes the PKCS12 key store and not the
Java Key Store (JKS). PKCS12 will be be the default key store in Java 9 and it's language independent. The project can be directly imported
as a Maven project or simply the project JAR can be used to inherit the rcm-fitness-common-keystore functionality.
</p>

For more information visit here: [Wiki](https://wiki.ent.vce.com/display/VSE/RCM+Fitness+Common+Keystore)

#### GIT Repository

The project is available on Git: [GIT_REPO](https://eos2git.cec.lab.emc.com/VCE-Symphony/rcm-fitness-common-keystore)

