package org.com.cip.cryptofiles;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *  Abstract class to Cryptography provider
 * 
 * @author Preda
 */
public abstract class Cryptography {
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
