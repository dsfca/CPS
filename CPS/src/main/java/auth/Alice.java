package auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.ini4j.InvalidFileFormatException;

import crypto.DiffieHellman;
import crypto.RSAProvider;
import crypto.SigMAuthentication;
import general.IniManager;

public class Alice extends Thread{
	private static final String ALICE_PRIVATE_KEY_PATH = "resources/A_private.key";
	private static final String ALICE_PUBLIC_KEY_PATH = "resources/A_public.key";
	private static final String BOB_PUBLIC_KEY_PATH = "resources/B_public.key";
	private static final String ALICE_ID = "A";
	private DiffieHellman DH1;
	private DiffieHellman DH2;
	private String Ra;
	private String Rb;
	private String t;
	private Key Kmac;
	private SecretKey Kkem;
	/*******************************************************************************************************************************************/
	private IniManager ini;
	
	private Socket bobSocket;
	private ObjectOutputStream bobObjectOutputStream;
	private ObjectInputStream bobObjectInputStream;
	

	public Alice() throws Exception {
		this.ini = new IniManager();
		
		this.bobSocket = (Socket) new Socket(ini.getBobHost(), ini.getBobServerPort());
		this.bobObjectOutputStream = new ObjectOutputStream(bobSocket.getOutputStream());
		this.bobObjectInputStream = new ObjectInputStream(bobSocket.getInputStream());
		RSAProvider.RSAKeyGenerator(ALICE_PRIVATE_KEY_PATH, ALICE_PUBLIC_KEY_PATH, ini.getKeystorePass());
		this.DH1 = new DiffieHellman();
		this.DH2 = new DiffieHellman();
	}
	
	
	public void run() {
		try {
			keyEncapsulationK(); //FUNCAO PARA REALIZAR DH KEY EXCHANGE
			sigMAauthentication();
		
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void keyEncapsulationK() throws Exception {
		byte[] p1 = this.DH1.getP().toByteArray();
		byte[] g1 = this.DH1.getG().toByteArray();
		byte[] myDH1PubKey = this.DH1.getPublicKey().getEncoded();
		
		byte[] p2 = this.DH2.getP().toByteArray();
		byte[] g2 = this.DH2.getG().toByteArray();
		byte[] myDH2PubKey = this.DH2.getPublicKey().getEncoded();
		//CREATE OBJECT AND THEN SEND TO BOB
		Object [] object = {p1, g1, myDH1PubKey, p2, g2, myDH2PubKey};
		this.bobObjectOutputStream.writeObject(object);
		//RECEIVE FROM BOB
		Object [] received = (Object[]) this.bobObjectInputStream.readObject();
		PublicKey BobPubKey1 = DiffieHellman.generatePublicKey((byte[])received[0]);
		PublicKey BobPubKey2 = DiffieHellman.generatePublicKey((byte[])received[1]);
		
		SecretKey Kkem1 = (SecretKey) this.DH1.agreeSecretKey(BobPubKey1, true);
		SecretKey Kkem2 = (SecretKey) this.DH2.agreeSecretKey(BobPubKey2, true);
		byte[] k1xork2 = xorWithKey(Kkem1.getEncoded(), Kkem2.getEncoded());
		
		
		this.Kkem = new SecretKeySpec(k1xork2, "AES");
		this.t = "(" + this.DH1.getPublicKey().hashCode() + "," +  BobPubKey1.hashCode() + "," + this.DH2.getPublicKey().hashCode() +"," +BobPubKey2.hashCode() +")";
		Key kmac1 = SigMAuthentication.generateKmac(Kkem1, DH1.getPublicKey(), BobPubKey1);
		Key kmac2 = SigMAuthentication.generateKmac(Kkem2, DH2.getPublicKey(), BobPubKey2);
		byte[] kma1XorKmac2 = xorWithKey(kmac1.getEncoded(), kmac2.getEncoded());
		this.Kmac  = new SecretKeySpec(kma1XorKmac2, "AES");
		
		System.out.println("ALICE: Diffie-Hellman key exchange completed");
	}
	

	public void sigMAauthentication() throws Exception {
		Ra = binNumber();
		this.bobObjectOutputStream.writeObject(Ra.getBytes());

		Object [] received = (Object[]) this.bobObjectInputStream.readObject();
		String BobID = (String) received[0];
		Rb = (String) received[1];
		byte[] Bsigma = (byte[]) received[2];
		byte[] BMac = (byte[]) received[3];
		
		String message = "0"+ t + "" + Ra + "" + Rb;
		if(SigMAuthentication.SVF(BOB_PUBLIC_KEY_PATH, message, Bsigma)) {
			message = "0" + BobID;
			if(SigMAuthentication.MVF(this.Kmac, message, BMac)) {
				message = "1"+ t + "" + Ra + "" + Rb;
				byte[] Asig = SigMAuthentication.Sig(ALICE_PRIVATE_KEY_PATH, message);
				message = "1" + ALICE_ID;
				byte[] AMac = SigMAuthentication.MAC(Kmac, message);
				
				Object [] object = {ALICE_ID, Asig, AMac};
				this.bobObjectOutputStream.writeObject(object);
				
				String sid = "(" + t + "," + Ra + "," + Rb + "," + ALICE_ID + "," + BobID + ")";
				
				Key K= SigMAuthentication.KeyDerivationFunction(Kkem, "KE"+sid);
				
				System.out.println("ALICE: Successful authentication key exchange");
				System.out.println("ALICE: agreed key: " + new String(K.getEncoded()));
				
			}else throw new Exception("bob mac didn't hold");
		}else throw new Exception("bob signature didn't hold");
		
	}
	
	public  String binNumber() {
	    Random rg = new Random();
	    int n = rg.nextInt(10);
	    return Integer.toBinaryString(n);
	}

	private byte[] xorWithKey(byte[] a, byte[] key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key[i%key.length]);
        }
        return out;
    }
	
	public static void main(String[] args) {

	}

}
