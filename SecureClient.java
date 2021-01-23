import java.io.*;  
import java.net.*;
import java.util.Scanner;
import java.nio.*;
import java.nio.charset.*;

public class SecureClient {

    public static Socket s;
    public static DataOutputStream dout;
    public static InputStream rd;

    static class ReceivedPacket {
        String command;
        int len;
        byte[] data;

        public String toString(){
            return command + "-" + len + "-" + new String(data, StandardCharsets.US_ASCII);
        }
    }

    public static void sendCommand(String command, int ll, byte[] data) throws IOException{
        byte[] a = command.getBytes("US-ASCII");
        byte[] b = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(ll).array();

        dout.write(a, 0, a.length);
        dout.write(b, 0, b.length);
        dout.write(data, 0, data.length);
    }
    
    public static ReceivedPacket recvCommand() throws IOException{
        byte[] command = new byte[8];
        rd.read(command, 0, 8);
        byte[] ll = new byte[4];
        rd.read(ll, 0, 4);
        int len = ByteBuffer.wrap(ll).order(ByteOrder.BIG_ENDIAN).getInt();
        byte[] data = new byte[len];
        rd.read(data, 0, len);

        ReceivedPacket rp = new ReceivedPacket();
        rp.command = new String(command, StandardCharsets.US_ASCII);
        rp.len = len;
        rp.data = data;

        return rp;
    }   

    public static byte[] getPK(byte[] cert){
        byte[] pk = new byte[8];
        System.arraycopy(cert, 19, pk, 0, pk.length);
        return pk;
    }

    public static byte[] getSignature(byte[] cert){
        byte[] signature = new byte[8];
        System.arraycopy(cert, 50, signature, 0, signature.length);
        return signature;
    }

    public static String getCA(byte[] cert){
        byte[] ca = new byte[10];
        System.arraycopy(cert, 30, ca, 0, ca.length);
        return new String(ca, StandardCharsets.US_ASCII);
    }

    public static void main (String[] args) throws IOException{
        int port = Integer.parseInt(args[0]);
        String ip = "127.0.0.1";
        CryptoHelper crypto;
        byte[] serverPublicKey;
        byte[] signature;
        String ca;

        while(true) {      
            // Instantiate CryptoHelper
            crypto = new CryptoHelper();
            s = new Socket(ip, port);
            dout = new DataOutputStream(s.getOutputStream());
            rd = s.getInputStream();

            // --- HANDSHAKE START
            String msg = "HELLOxxx"; 
            sendCommand(msg, 0, new byte[0]);

            // Receive the certificate
            ReceivedPacket rp = recvCommand();
            byte[] cert = rp.data;
            
            // Get necessary fields from the certificate
            signature = getSignature(cert);
            ca = getCA(cert); 
            serverPublicKey = getPK(cert);

            // Verification is successful:
            if (crypto.verifySignature(cert, signature, ca)) 
                break;
            // Verification fails:
            else {
                System.out.println("Certificate NOT verified. Reattempting connection...");
                s.close();
                dout.close();
                rd.close();
            }

        }
        // Create and send encrypted secret
        int secret = crypto.generateSecret();
        byte[] secretEncrypted = crypto.encryptSecretAsymmetric(secret, serverPublicKey);
        
        sendCommand("SECRETxx", secretEncrypted.length, secretEncrypted);
        // --- HANDSHAKE END

        // --- AUTHENTICATION START
        sendCommand("STARTENC", 0, new byte[0]); // Start encryption

        // Send encrypted authentication info
        byte[] authEncrypted = crypto.encryptSymmetric("bilkent cs421", secret);
        sendCommand("AUTHxxxx", authEncrypted.length, authEncrypted); // Start encryption

        // Receive authentication response
        byte[] data = recvCommand().data;
        String response = crypto.decryptSymmetric(data, secret);
        // System.out.println(response);  // This should be "OK"
        if (!(response.equals("OK"))){
            System.out.println("Wrong username or password."); 
        }

        sendCommand("ENDENCxx", 0, new byte[0]); // End encryption
        
        // --- AUTHENTICATION END
        // --- VIEW PUBLIC POSTS START
        sendCommand("PUBLICxx", 0, new byte[0]);
        data = recvCommand().data;

        // Decode the byte array into a string & display
        response = new String(data, StandardCharsets.US_ASCII);
        System.out.println(response);
        // --- VIEW PUBLIC POSTS END

        // --- VIEW PRIVATE MESSAGES START
        sendCommand("STARTENC", 0, new byte[0]); // Start encryption
        sendCommand("PRIVATEx", 0, new byte[0]);
        data = recvCommand().data;

        // Receive, decrypt & display
        response = crypto.decryptSymmetric(data, secret);
        System.out.println(response);

        sendCommand("ENDENCxx", 0, new byte[0]); // End encryption
        // --- VIEW PRIVATE MESSAGES END
        // LOGOUT
        sendCommand("LOGOUTxx", 0, new byte[0]);
        s.close();
        dout.close();
        rd.close();
    }
}