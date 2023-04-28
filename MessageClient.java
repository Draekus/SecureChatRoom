package org.example;

import java.io.*;
import java.net.Socket;
import java.util.Scanner;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

import java.nio.charset.StandardCharsets;

public class MessageClient {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        //  Send Serialized Student over the Wire
        Socket socket = new Socket("localhost", 8000);

        // Create a Scanner object
        Scanner scanner = new Scanner(System.in);

        // Create object input stream to read data from server
        ObjectInputStream fromServer = new ObjectInputStream(socket.getInputStream());

        // Create object output stream to send data to server
        ObjectOutputStream toServer = new ObjectOutputStream(socket.getOutputStream());
        
        // Generate client DH key pair with 2048-bit key size
        System.out.println("CLIENT: Generating Diffie-Hellman keypair ...");
        KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
        clientKpairGen.initialize(2048);
        KeyPair clientKpair = clientKpairGen.generateKeyPair();

        // Initialize client DH KeyAgreement
        System.out.println("CLIENT: Key Agreement Initialization ...");
        KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKpair.getPrivate());

        // Encode client public key 
        EncodedKey clientPubKeyEnc = new EncodedKey(clientKpair.getPublic().getEncoded());
        
        // Send encoded key to server
        toServer.writeObject(clientPubKeyEnc);

        // Receive encoded key from server
        EncodedKey serverPubKeyEnc = (EncodedKey) fromServer.readObject();

        // Client generates server's public key
        System.out.println("CLIENT: Executing PHASE1 ...");
        KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc.getKey());
        PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
        clientKeyAgree.doPhase(serverPubKey, true);

        // DH key agreement completed
        System.out.println("CLIENT: DH key exchange completed successfully!");

        // Generate shared secret
        byte[] clientSharedSecret = clientKeyAgree.generateSecret();
        int clientLen = clientSharedSecret.length;

        System.out.println("Client Shared Secret: " + toHexString(clientSharedSecret));

        // Create secret key spec
        SecretKeySpec clientAesKey = new SecretKeySpec(clientSharedSecret, 0, 16, "AES");

        // -------------------- SETUP COMPLETE -----------------------------------

        // Create new thread
        Thread receiveThread = new Thread(() -> {
            // Create empty message object
            Message received;
            try {
                while ((received = (Message) fromServer.readObject()) != null) {
                    // Decrypt message
                    AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
                    aesParams.init(received.getEncodedParams());
                    Cipher clientCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    clientCipher.init(Cipher.DECRYPT_MODE, clientAesKey, aesParams);
                    byte[] recovered = clientCipher.doFinal(received.getCipherText());
                    // Convert raw bytes to string
                    String decodedMessage = new String(recovered, StandardCharsets.UTF_8);
                    // Print message to console
                    System.out.println(received.getSender() + ": " + decodedMessage);
                }
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Connection lost: " + e.getMessage());
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        });

        receiveThread.start();

        // Get clients name
        System.out.print("Enter your name: ");
        String name = scanner.nextLine();

        String user_message;
        while ((user_message = scanner.nextLine()) != null) {
            // Encrypt message
            Cipher clientCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            clientCipher.init(Cipher.ENCRYPT_MODE, clientAesKey);
            byte[] cleartext = user_message.getBytes();
            byte[] ciphertext = clientCipher.doFinal(cleartext);

            // Extract encoded parameters from cipher
            byte[] encodedParams = clientCipher.getParameters().getEncoded();

            // Create new message
            Message clientMessage = new Message(name, ciphertext, encodedParams);

            // Send message to server and clear buffer
            toServer.writeObject(clientMessage);
            toServer.flush();
        }

    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
