package br.org.cip.cryptofiles;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;

/**
 * Class used to encrypt based on properties file
 *
 * @author Preda
 */
public class EncryptMain extends CryptographyAbstract {

    private final String sender;
    private final String receiver;
    private final File pubKeyRing;
    private final File secKeyRing;
    private final String secKeyRingPassword;

    /**
     * Default constructor
     *
     * @author Preda
     * @param pubKeyRing
     * @param receiver
     * @param secKeyRing
     * @param secKeyRingPassword
     * @param sender
     */
    public EncryptMain(final String sender, final String receiver, final File pubKeyRing,
            final File secKeyRing, final String secKeyRingPassword) {
        super();
        this.sender = sender;
        this.receiver = receiver;
        this.pubKeyRing = pubKeyRing;
        this.secKeyRing = secKeyRing;
        this.secKeyRingPassword = secKeyRingPassword;
    }

    /**
     * Encrypt source file (path) to dest file
     *
     * @param sourceFile
     * @param destFile
     */
    public void encrypt(final Path sourceFile, final Path destFile) {
        try {
            encrypt(Files.newInputStream(sourceFile), destFile);
        } catch (IOException ex) {
            Logger.getLogger(EncryptMain.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Encrypt source inputStream to dest (path)
     *
     * @param sourceStream
     * @param destFile
     */
    public void encryptFromSourceStream(final ByteArrayOutputStream sourceStream, final Path destFile)  {

        try {
            long startTime = System.currentTimeMillis();

            System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

            //Config keyingConfig (pubkey, seckey and password)
            final KeyringConfig k2 = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                    secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

            //Open all resources 
            final OutputStream fileOutput = Files.newOutputStream(destFile);
            //Write to dest file using the buffsize (fixed parameter in abstract super)
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);
            try (OutputStream outputStream = BouncyGPG
                    .encryptToStream()
                    .withConfig(k2)
                    .withAlgorithms(getAlgo())
                    .toRecipient(receiver)
                    .andSignWith(sender)
                    .armorAsciiOutput()
                    .andWriteTo(bufferedOut)) {
                Streams.writeBufTo(sourceStream, outputStream);
                outputStream.flush();
               // outputStream.close();
            }
            
            long endTime = System.currentTimeMillis();
            System.out.println(sourceStream.toString());

            System.out.format("Encryption BUFF took %.2f s\n", ((double) endTime - startTime) / 1000);
        } catch (IOException | PGPException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.format("ERROR: %s", e.getMessage());
            Logger.getLogger(EncryptMain.class.getName()).log(Level.SEVERE, null, e);
        } 
    }

    /**
     * Encrypt source inputStream to dest (path)
     *
     * @param sourceStream
     * @param destFile
     */
    public void encrypt(final InputStream sourceStream, final Path destFile) {
        try {
            long startTime = System.currentTimeMillis();

            System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

            //Config keyingConfig (pubkey, seckey and password)
            final KeyringConfig k2 = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                    secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

            //Open all resources 
            try (
                    final OutputStream fileOutput = Files.newOutputStream(destFile);
                    //Write to dest file using the buffsize (fixed parameter in abstract super)
                    final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);
                    final OutputStream outputStream = BouncyGPG
                            .encryptToStream()
                            .withConfig(k2)
                            .withAlgorithms(getAlgo())
                            .toRecipient(receiver)
                            .andSignWith(sender)
                            .armorAsciiOutput()
                            .andWriteTo(bufferedOut);
                    final InputStream is = sourceStream) {
                Streams.pipeAll(is, outputStream);
            }
            long endTime = System.currentTimeMillis();

            System.out.format("Encryption took %.2f s\n", ((double) endTime - startTime) / 1000);
        } catch (IOException | PGPException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.format("ERROR: %s", e.getMessage());
            Logger.getLogger(EncryptMain.class.getName()).log(Level.SEVERE, null, e);
        }
    }

    /**
     * Get outputStream from destFile to write
     *
     * @param destFile
     * @return OutputStream
     */
    public OutputStream getOutputStreamToEncrypt(final Path destFile) {
        OutputStream outputStream = null;
        try {
            System.out.format("-- Using a write buffer of %d bytes\n", BUFFSIZE);

            final OutputStream fileOutput = Files.newOutputStream(destFile);

            //Write to dest file using the buffsize (fixed parameter in abstract super)
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);

            //Config keyingConfig (pubkey, seckey and password)
            final KeyringConfig k2 = KeyringConfigs.withKeyRingsFromFiles(pubKeyRing,
                    secKeyRing, KeyringConfigCallbacks.withPassword(secKeyRingPassword));

            //Write to dest file using the buffsize (fixed parameter in abstract super)
            //final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput, BUFFSIZE);
            outputStream = BouncyGPG
                    .encryptToStream()
                    .withConfig(k2)
                    .withAlgorithms(getAlgo())
                    .toRecipient(receiver)
                    .andSignWith(sender)
                    .armorAsciiOutput()
                    .andWriteTo(bufferedOut);

        } catch (IOException | PGPException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.format("ERROR: %s", e.getMessage());
            Logger.getLogger(EncryptMain.class.getName()).log(Level.SEVERE, null, e);
        }
        return outputStream;
    }
}