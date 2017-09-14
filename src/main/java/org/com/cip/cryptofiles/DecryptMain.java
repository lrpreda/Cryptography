package org.com.cip.cryptofiles;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

public class DecryptMain {

    private File pubKeyRing;
    private File secKeyRing;
    private String secKeyRingPassword ;

    void DecryptMain(final File pubKeyRing, final File secKeyRing, final String secKeyRingPassword){
        this.pubKeyRing = pubKeyRing;
        this.secKeyRing = secKeyRing;
        this.secKeyRingPassword = secKeyRingPassword;
    }
    
    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void decrypt(final Path sourceFile, final Path destFile) {
        try {
            installBCProvider();
            long startTime = System.currentTimeMillis();

            final int BUFFSIZE = 8 * 1024;
            System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

            final KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                    secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

            try (
                    final InputStream cipherTextStream = Files.newInputStream(sourceFile);
                    final OutputStream fileOutput = Files.newOutputStream(destFile);
                    final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);
                    final InputStream plaintextStream = BouncyGPG
                    .decryptAndVerifyStream()
                    .withConfig(keyringConfig)
                    .andValidateSomeoneSigned()
                    .fromEncryptedInputStream(cipherTextStream)) {
                Streams.pipeAll(plaintextStream, bufferedOut);
            }
            long endTime = System.currentTimeMillis();

            System.out.format("Decryption took %.2f s\n", ((double) endTime - startTime) / 1000);
        } catch (Exception e) {
            System.err.format("ERROR: %s", e.getMessage());
            e.printStackTrace();
        }
    }

}
