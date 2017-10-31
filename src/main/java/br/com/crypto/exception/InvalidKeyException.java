/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.crypto.exception;

/**
 * Exception for invalid Key Initialization
 * @author lrpre
 */
public class InvalidKeyException extends Exception {
    
    public InvalidKeyException(){
        super();
    }
    
    public InvalidKeyException(String msg){
        super(msg);
    }
}
