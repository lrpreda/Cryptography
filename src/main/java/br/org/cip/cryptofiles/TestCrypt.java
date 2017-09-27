/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.org.cip.cryptofiles;

import br.org.cip.io.EnhancedByteArrayOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import br.org.cip.cryptofiles.utils.LoadProperties;

/**
 *
 * @author lrpre
 */
public class TestCrypt {

    public static void main(String args[]) throws Exception {
        LoadProperties lProp;
        lProp = new LoadProperties("config.properties");

        //Used to encrypt
        File senderPrivateKey = new File(lProp.getValue("senderPrivateKey"));
        File receiverPublicKey = new File(lProp.getValue("receiverPublicKey"));

        //Used to decrypt
        File receiverPrivateKey = new File(lProp.getValue("receiverPrivateKey"));
        File senderPublicKey = new File(lProp.getValue("senderPublicKey"));

        File fileToBeEncrypted = new File("c://dev_tools//FILETO.ORIGINAL");
        File fout = new File("c://dev_tools//FILEENCR.kry");
        File fDec = new File("c://dev_tools//FILE_DEC.txt");

        Encrypt encry = new Encrypt(lProp.getValue("sender"), lProp.getValue("receiver"), receiverPublicKey, senderPrivateKey, lProp.getValue("senderKeyPassword"));
        encry.encrypt(new FileInputStream(fileToBeEncrypted), fout.toPath());

        Decrypt decry = new Decrypt(senderPublicKey, receiverPrivateKey, lProp.getValue("receiverKeyPassword"));
        decry.decrypt(new FileInputStream(fout), fDec.toPath());

        String OUTPUT_FILE = "c://dev_tools//testFile.cry";
        File fout2 = new File(OUTPUT_FILE);
        
        Encrypt encry2 = new Encrypt(lProp.getValue("sender"), lProp.getValue("receiver"), receiverPublicKey, senderPrivateKey, lProp.getValue("senderKeyPassword"));

        EnhancedByteArrayOutputStream baOut = new EnhancedByteArrayOutputStream();
        String content = new String("Leandro");
       String content2;
//        byte[] bytes = content.getBytes();
       
        //OutputStream baOut = encry2.getOutputStreamToEncrypt(new File(OUTPUT_FILE).toPath());       
        //out.write(bytes, 4, 10);
        baOut.write(content);
        for (int i = 0; i < 10; i++) {
            content2 = "Write : " + i;
            baOut.write(content2);
            baOut.nextLine();
        }
        encry2.encryptFromSourceStream(baOut, fout2.toPath());

        File fDec2 = new File("c://dev_tools//FILE_DEC2.txt");

        Decrypt decry2 = new Decrypt(senderPublicKey, receiverPrivateKey, lProp.getValue("receiverKeyPassword"));
        decry2.decrypt(new FileInputStream(fout2), fDec2.toPath());

    }

}
