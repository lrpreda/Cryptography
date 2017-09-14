package org.com.cip.cryptofiles;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

public class EncryptMain {

    private String sender;
    private String recipient;
    private File pubKeyRing;
    private File secKeyRing;
    private String secKeyRingPassword;

    void EncryptMain(final String sender, final String recipient, final File pubKeyRing,
            final File secKeyRing, final String secKeyRingPassword) {
        this.sender = sender;
        this.recipient = recipient;
        this.pubKeyRing = pubKeyRing;
        this.secKeyRing = secKeyRing;
        this.secKeyRingPassword = secKeyRingPassword;
    }

    static void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void encrypt(final Path sourceFile,final Path destFile) {
        try {
            encrypt(Files.newInputStream(sourceFile), destFile);
        } catch (IOException ex) {
            Logger.getLogger(EncryptMain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void encrypt(final InputStream sourceStream, final Path destFile) {
        try {
            installBCProvider();
            long startTime = System.currentTimeMillis();

            final int BUFFSIZE = 8 * 1024;
            System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

            final KeyringConfig keyringConfig = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                    secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

            try (
                    final OutputStream fileOutput = Files.newOutputStream(destFile);
                    final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);
                    final OutputStream outputStream = BouncyGPG
                    .encryptToStream()
                    .withConfig(keyringConfig)
                    .withStrongAlgorithms()
                    .toRecipient(recipient)
                    .andSignWith(sender)
                    .binaryOutput()
                    .andWriteTo(bufferedOut);
                    final InputStream is = sourceStream) {
                Streams.pipeAll(is, outputStream);
            }
            long endTime = System.currentTimeMillis();

            System.out.format("Encryption took %.2f s\n", ((double) endTime - startTime) / 1000);
        } catch (Exception e) {
            System.err.format("ERROR: %s", e.getMessage());
            e.printStackTrace();
        }
    }

}
