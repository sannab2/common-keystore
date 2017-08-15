/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * This is the properties config file for this project
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries. All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 */
public class EncryptionPropertiesConfig
{
    /**
     * Default Constructor - Scope is Private
     */
    private EncryptionPropertiesConfig()
    {
        // Default Private Constructor
        // Added just to hide the class instantiation
    }

    /**
     * This method loads the properties file.
     *
     * @return Properties instance containing a set of properties.
     * @throws IOException IOException
     */
    public static Properties loadProperties() throws IOException
    {
        final Properties properties = new Properties();
        final InputStream in = EncryptionPropertiesConfig.class.getClassLoader().getResourceAsStream("encryption.properties");
        properties.load(in);
        return properties;
    }
}
