/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 *
 * @author lrpre
 */
public class LoadProperties {

    private String filePropName;
    private InputStream input = null;
    private Properties prop = new Properties();

    public LoadProperties(String fileName) {
        this.filePropName = fileName;
        try {
           input= getClass().getClassLoader().getResourceAsStream(filePropName);
             
            prop.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    public String getValue(final String propValue) {
        return prop.getProperty(propValue);
    }
}
