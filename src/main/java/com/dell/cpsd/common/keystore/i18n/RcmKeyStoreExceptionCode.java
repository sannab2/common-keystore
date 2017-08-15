/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.i18n;

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * RCM Keystore exception code.
 * <p>
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @since 1.0
 */
public enum RcmKeyStoreExceptionCode
{
    ERROR1_E("EKSO1001E"),
    ERROR2_E("EKSO1002E");

    private static ResourceBundle BUNDLE = ResourceBundle.getBundle(RcmKeyStoreErrorBundle.class.getName());

    private final String messageCode;

    RcmKeyStoreExceptionCode(String messageCode)
    {
        this.messageCode = messageCode;
    }

    public String getMessage()
    {
        try
        {
            return BUNDLE.getString(this.messageCode);

        }
        catch (MissingResourceException exception)
        {
            return this.messageCode;
        }
    }

    public String getMessage(Object... params)
    {
        String message;

        try
        {
            message = BUNDLE.getString(this.messageCode);

        }
        catch (MissingResourceException exception)
        {
            return this.messageCode;
        }

        if ((params == null) || (params.length == 0))
        {
            return message;
        }

        return MessageFormat.format(message, params);
    }
}

