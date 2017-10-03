package br.org.cip.cryptofiles;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.util.io.Streams;

/**
 * Class used to decrypt file based on config properties
 *
 * @author Preda
 */
public class Decrypt extends CryptographyAbstract {

    private final File pubKeyRing;
    private final File secKeyRing;
    private final String secKeyRingPassword;

    /**
     * Default Constructor
     *
     * @param pubKeyRing
     * @param secKeyRing
     * @param secKeyRingPassword
     */
    public Decrypt(final File pubKeyRing, final File secKeyRing, final String secKeyRingPassword) {
        super();
        this.pubKeyRing = pubKeyRing;
        this.secKeyRing = secKeyRing;
        this.secKeyRingPassword = secKeyRingPassword;
    }

    /**
     * Decrypt source file (inputStream) to DestFile (path)
     *
     * @param sourceStream
     * @param destFile
     */
    public void decrypt(final InputStream sourceStream, final Path destFile) {
        try {

            final KeyringConfig keyringConfigFor = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                    secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));
            //Open all resources 
            try (
                    final OutputStream fileOutput = Files.newOutputStream(destFile);
                    //output using the default buffer size
                    final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);
                    final InputStream plaintextStream = BouncyGPG
                            .decryptAndVerifyStream()
                            .withConfig(keyringConfigFor)
                            .andValidateSomeoneSigned()
                            .fromEncryptedInputStream(sourceStream)) {
                Streams.pipeAll(plaintextStream, bufferedOut);
            }

        } catch (IOException
                | NoSuchProviderException e) {
            System.err.format("ERROR: %s", e.getMessage());
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, e);
        }
    }

    /**
     * Decrypt source file (path) to DestFile (path)
     *
     * @param sourceFile
     * @param destFile
     */
    public void decrypt(final Path sourceFile, final Path destFile) {
        try {
            decrypt(Files.newInputStream(sourceFile), destFile);
        } catch (IOException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
