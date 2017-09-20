package br.org.cip.cryptofiles;

import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
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

    /**
     * initialize BC provider
     */
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Default constructor
     */
    public CryptographyAbstract() {
        installBCProvider();
    }

    //Get String algorithms AES 256
    public PGPAlgorithmSuite getAlgo() {
        return new PGPAlgorithmSuite(
                PGPHashAlgorithms.SHA_256,
                PGPSymmetricEncryptionAlgorithms.AES_256,
                PGPCompressionAlgorithms.ZLIB
        );

    }
    
}
