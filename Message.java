package org.example;

import java.io.Serializable;

public class Message implements Serializable {
    private String sender;
    private byte[] cipherText;

    private byte[] encodedParams;

    public Message(String sender, byte[] cipherText, byte[] encodedParams) {
        this.sender = sender;
        this.cipherText = cipherText;
        this.encodedParams = encodedParams;
    }

    public String getSender() {
        return sender;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getEncodedParams() {
        return encodedParams;
    }
}
