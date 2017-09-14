/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.com.cip.cryptofiles;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.com.cip.cryptofiles.utils.LoadProperties;

/**
 *
 * @author lrpre
 */
public class TestCrypt {
    
    public static void main(String args[]) throws Exception{
        LoadProperties lProp = new LoadProperties("config.properties");
        File pubKey = new File(lProp.getValue("publicKey"));
        File seckey = new File(lProp.getValue("privateKey"));
        
        EncryptMain encry = new EncryptMain(lProp.getValue("sender"), lProp.getValue("receipt"), pubKey, seckey, lProp.getValue("keyPassword"));
       File f = new File("c://dev_tools//FILETO.txt");
       File fout = new File("c://dev_tools//FILETO2.txt");
       
        encry.encrypt(new FileInputStream(f), fout.toPath());
    }
    
}
