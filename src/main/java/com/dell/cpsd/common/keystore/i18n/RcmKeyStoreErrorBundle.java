/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 */

package com.dell.cpsd.common.keystore.i18n;

import java.util.ListResourceBundle;

/**
 * RCM Keystore error bundle
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * Dell EMC Confidential/Proprietary Information
 * </p>
 *
 * @version 1.0
 * @since 1.0
 */
public class RcmKeyStoreErrorBundle extends ListResourceBundle
{

    private static final Object[][] CONTENTS = {
            {"EKSO1001E", "EKSO1001E - Error Creating the Key Store for service name [{0}] at location [{1}] with Key Alias [{2}]"},
            {"EKSO1002E", "EKSO1002E "}};

    @Override
    protected Object[][] getContents()
    {
        return CONTENTS;
    }
}

