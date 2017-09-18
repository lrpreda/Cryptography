/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.com.cip.cryptofiles;

import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import org.com.cip.cryptofiles.utils.LoadProperties;

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

        EncryptMain encry = new EncryptMain(lProp.getValue("sender"), lProp.getValue("receiver"), receiverPublicKey, senderPrivateKey, lProp.getValue("senderKeyPassword"));
        encry.encrypt(new FileInputStream(fileToBeEncrypted), fout.toPath());

        DecryptMain decry = new DecryptMain(senderPublicKey, receiverPrivateKey, lProp.getValue("receiverKeyPassword"));
        decry.decrypt(new FileInputStream(fout), fDec.toPath());

        String OUTPUT_FILE = "c://dev_tools//testFile.cry";
        EncryptMain encry2 = new EncryptMain(lProp.getValue("sender"), lProp.getValue("receiver"), receiverPublicKey, senderPrivateKey, lProp.getValue("senderKeyPassword"));
        
        //BufferedOutputStream buffOut = new BufferedOutputStream(new FileOutputStream(new File(OUTPUT_FILE)));
        String content = new String("Leandro");
        String content2;
        byte[] bytes = content.getBytes();

        OutputStream out = encry2.getOutputStreamToEncrypt(new File(OUTPUT_FILE).toPath());
        out.write(bytes);
        out.write(bytes[0]);
        //out.write(bytes, 4, 10);
        for (int i = 0; i < 10; i++) {
            content2 = "Write : " + i;
            out.write(content2.getBytes());
        }
        out.flush();
        out.close();
//
        File fout2 = new File(OUTPUT_FILE);
        File fDec2 = new File("c://dev_tools//FILE_DEC2.txt");
        
        DecryptMain decry2 = new DecryptMain(senderPublicKey, receiverPrivateKey, lProp.getValue("receiverKeyPassword"));
        decry2.decrypt(new FileInputStream(fout2), fDec2.toPath());
        
    }

}
