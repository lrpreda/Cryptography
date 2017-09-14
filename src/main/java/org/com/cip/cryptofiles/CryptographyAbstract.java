package org.com.cip.cryptofiles;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *  Abstract class to CryptographyAbstract provider
 * 
 * @author Preda
 */
public abstract class CryptographyAbstract {
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
