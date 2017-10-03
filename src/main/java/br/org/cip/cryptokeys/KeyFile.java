/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.org.cip.cryptokeys;

import java.io.File;

/**
 * Object representing the KeyFile
 * 
 * @author Preda
 */
public class KeyFile {
    
    private File kFile;
    private String pwd=null;
    private boolean isPrivateKey;
    private String senderORreceiver;
    
    /**
     * Constructor for public key
     * 
     * @param key 
     * @param sORr 
     */
    public KeyFile(File key, String sORr){
        this(key,null, sORr);
    }
    
    /**
     * Constructor of private Key, is passWd is null the key is public
     * 
     * @param key
     * @param passWd 
     * @param sORr
     */
    public KeyFile(File key, String passWd, String sORr){
        kFile=key;
        isPrivateKey=(passWd!=null);
        pwd=passWd;
        senderORreceiver = sORr;
    }

    /**
     * Return File representing the Key
     * @return File
     */
    public File getkFile() {
        return kFile;
    }

    /**
     * Return the password
     * @return String
     */
    public String getPwd() {
        return pwd;
    }

    /**
     * Return is the key is private
     * @return boolean
     */
    public boolean isIsPrivateKey() {
        return isPrivateKey;
    }
    
    /**
     * Get Sender or Receiver signature
     * @return String
     */
    public String getSenderORreceiver(){
        return senderORreceiver;
    }
   
}
