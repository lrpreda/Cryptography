package br.org.cip.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * class to extend ByteArrayOutputStream to accept String and implement the next line break
 * 
 * @author Preda
 */
public class EnhancedByteArrayOutputStream extends ByteArrayOutputStream {

    /**
     * Break Line specific for running OS
     */
    protected byte[] breakLine = System.getProperty("line.separator").getBytes();
    
    /**
     * Default constructor
     */
    public EnhancedByteArrayOutputStream() {
        super();
    }

    public EnhancedByteArrayOutputStream(int size) {
        super(size);
    }
    
    /**
     * Break Line using OS Break Line 
     * 
     * @throws IOException 
     */
    public void nextLine() throws IOException{
        write(breakLine);
        
    }
    
    /**
     * Write to buffer using String
     * 
     * @param strS
     * @throws IOException
     */
    public void write(String strS) throws IOException {
        write(strS.getBytes());
    }
    
}
