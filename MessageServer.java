package org.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

import java.nio.charset.StandardCharsets;

/**
 * Secure Messaging Server
 */
public class MessageServer {
    private static final int PORT = 8000;
    private static final int DEFAULT_NUM_THREADS = 6;

    // Create hashmap for storing client output streams and keys
    private static HashMap<ObjectOutputStream, SecretKeySpec> clientKeys = new HashMap<>();
    // Create client list to store output streams
    private static HashSet<ObjectOutputStream> clients = new HashSet<>();

    public static void main( String[] args ) throws ClassNotFoundException, IOException {

        // Instantiate logger
        Logger logger = LoggerFactory.getLogger(MessageServer.class);

        // Start server
        logger.info("Chat Room Server Started on PORT:" + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                new HandleMessageRequest(serverSocket.accept()).start();
            }
        }

    }

    /**
     * On client connection performs handshake then waits on messages
     */
    public static class HandleMessageRequest extends Thread {
        private Socket socket;
        private ObjectOutputStream toClient;
        private ObjectInputStream objectInputStream;

        // Instantiate logger
        Logger logger = LoggerFactory.getLogger(org.example.HandleMessageRequest.class);

        /**
         * Constructor.
         *
         * @param socket The socket to connect to
         */
        public HandleMessageRequest(Socket socket) throws IOException, ClassNotFoundException {
            this.socket = socket;

            // Create object output stream to send data to client
            this.toClient = new ObjectOutputStream(socket.getOutputStream());
            // Create object input stream to receive data from client
            this.objectInputStream = new ObjectInputStream(socket.getInputStream());
        }

        /**
         * Helper method for toHexString
         */
        public void byte2hex(byte b, StringBuffer buf) {
            char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                    '9', 'A', 'B', 'C', 'D', 'E', 'F'};
            int high = ((b & 0xf0) >> 4);
            int low = (b & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
        }

        /**
         * Convert byte array to hex string
         */
        public String toHexString(byte[] block) {
            StringBuffer buf = new StringBuffer();
            int len = block.length;
            for (int i = 0; i < len; i++) {
                byte2hex(block[i], buf);
                if (i < len - 1) {
                    buf.append(":");
                }
            }
            return buf.toString();
        }

        /**
         * Reads encrypted message data from client then decrypts it. The message is then re-encrypted
         * for each client and broadcast
         */
        @Override
        public void run() {
            try {

                // Receive encoded public key from client
                logger.info("Receiving public key from client ...");
                EncodedKey clientPubKeyEnc = (EncodedKey) this.objectInputStream.readObject();
                //System.out.println(new String(clientPubKeyEnc.getKey()));

                // Instantiate DH public key from client's encoded key
                KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc.getKey());

                // Generate client public key
                logger.info("Generating client public key ...");
                PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

                // Extract DH parameters from client public key
                DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey) clientPubKey).getParams();

                // Generate server DH key pair
                logger.info("Generating server DH key pair ...");
                KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
                serverKpairGen.initialize(dhParamFromClientPubKey);
                KeyPair serverKpair = serverKpairGen.generateKeyPair();

                // Initialize DH Key Agreement
                logger.info("Initializing server key agreement ...");
                KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
                serverKeyAgree.init(serverKpair.getPrivate());

                // Encode server public key
                EncodedKey serverPubKeyEnc = new EncodedKey(serverKpair.getPublic().getEncoded());

                // Send server public key to client
                this.toClient.writeObject(serverPubKeyEnc);

                // Execute phase 1
                logger.info("Executing phase 1 of DH ...");
                serverKeyAgree.doPhase(clientPubKey, true);

                // Generate shared secret
                byte[] serverSharedSecret = serverKeyAgree.generateSecret();
                int serverLen = serverSharedSecret.length;

                logger.info("DH key exchange completed successfully");
                System.out.println("Server Shared Secret: " + toHexString(serverSharedSecret));

                // Generate secret key spec
                logger.info("Generating secret key spec ...");
                SecretKeySpec serverAesKey = new SecretKeySpec(serverSharedSecret, 0, 16, "AES");

                // ----------------------- SETUP ENDED -----------------------------------------------------

                synchronized (clients) {
                    clients.add(toClient);
                    clientKeys.put(toClient, serverAesKey);
                }

                // Receive message
                Message clientMessage;
                while ((clientMessage = (Message) this.objectInputStream.readObject()) != null) {
                    // Decrypt message
                    logger.info("Decrypting message ...");
                    AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
                    aesParams.init(clientMessage.getEncodedParams());
                    Cipher serverCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    serverCipher.init(Cipher.DECRYPT_MODE, serverAesKey, aesParams);
                    byte[] recovered = serverCipher.doFinal(clientMessage.getCipherText());

                    // Extract sender from message
                    String sender = clientMessage.getSender();

                    // Report received message
                    String decodedMessage = new String(recovered, StandardCharsets.UTF_8);
                    logger.info("Received Message - Sender: " + sender + " Message: " + decodedMessage);

                    // Iterate over client list
                    for (ObjectOutputStream writer : clients) {
                        // Obtain correct key from hashmap
                        SecretKeySpec serverMessageKey = clientKeys.get(writer);

                        // Encrypt message
                        Cipher clientCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        clientCipher.init(Cipher.ENCRYPT_MODE, serverMessageKey);
                        byte[] ciphertext = clientCipher.doFinal(recovered);

                        // Extract encoded parameters from cipher
                        byte[] encodedParams = clientCipher.getParameters().getEncoded();

                        // Create new message
                        Message newMessage = new Message(sender, ciphertext, encodedParams);

                        // Send message to client and flush buffer
                        writer.writeObject(newMessage);
                        writer.flush();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } finally {
                // Remove client if it disconnects
                if (toClient != null) {
                    synchronized (clients) {
                        clients.remove(toClient);
                    }
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }
    }
}
