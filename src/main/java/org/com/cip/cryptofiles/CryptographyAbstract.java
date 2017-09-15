package org.com.cip.cryptofiles;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Abstract class to CryptographyAbstract provider
 *
 * @author Preda
 */
public abstract class CryptographyAbstract {

    //Buffer sized used to flush the file
    //Can be tunned for performance problems
    final int BUFFSIZE = 8 * 1024;

    //Add BC provider
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
