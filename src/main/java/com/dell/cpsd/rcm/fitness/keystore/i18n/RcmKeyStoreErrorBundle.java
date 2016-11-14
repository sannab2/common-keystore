/**
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 */

package com.dell.cpsd.rcm.fitness.keystore.i18n;

import java.util.ListResourceBundle;

/**
 * TODO: Document usage.
 * <p>
 * <p>
 * Copyright &copy; 2016 Dell Inc. or its subsidiaries.  All Rights Reserved.
 * VCE Confidential/Proprietary Information
 * </p>
 *
 * @since Vision 1.0.0
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

