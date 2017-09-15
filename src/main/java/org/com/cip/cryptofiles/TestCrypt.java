/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.com.cip.cryptofiles;

import java.io.File;
import java.io.FileInputStream;
import org.com.cip.cryptofiles.utils.LoadProperties;

/**
 *
 * @author lrpre
 */
public class TestCrypt {
    
    public static void main(String args[]) throws Exception{
        LoadProperties lProp;
        lProp = new LoadProperties("config.properties");
        
        //Used to encrypt
        File senderPrivateKey = new File(lProp.getValue("senderPrivateKey"));
        File receiverPublicKey= new File(lProp.getValue("receiverPublicKey"));
        
        //Used to decrypt
        File receiverPrivateKey = new File(lProp.getValue("receiverPrivateDecryKey"));
        File senderPublicKey = new File(lProp.getValue("senderPublicDecryKey"));
        
        
       File fileToBeEncrypted = new File("c://dev_tools//FILETO.ORIGINAL");
       File fout = new File("c://dev_tools//FILEENCR.kry");
       File fDec = new File ("c://dev_tools//FILE_DEC.txt");
        
       EncryptMain encry = new EncryptMain(lProp.getValue("sender"), lProp.getValue("receiver"), receiverPublicKey, senderPrivateKey, lProp.getValue("senderKeyPassword"));
       encry.encrypt(new FileInputStream(fileToBeEncrypted), fout.toPath());

       DecryptMain decry = new DecryptMain(senderPublicKey, receiverPrivateKey, lProp.getValue("receiverKeyPassword"));
       decry.decrypt(new FileInputStream(fout),fDec.toPath());
//       File f = new File("c://dev_tools//FILETO.txt");
//       File fout = new File("c://dev_tools//FILETO2.txt");
//       
//        encry.encrypt(new FileInputStream(f), fout.toPath());
    }
    
}
