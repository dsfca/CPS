package auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.Random;

import javax.crypto.SecretKey;

import org.ini4j.InvalidFileFormatException;

import crypto.DiffieHellman;
import crypto.RSAProvider;
import crypto.SigMAuthentication;
import general.IniManager;

public class Bob extends Thread {
	
	private IniManager ini;
	private ServerSocket ssocket;
	
	private static final String BOB_ID = "B";
	private static final String BOB_PRIVATE_KEY_PATH = "resources/" + BOB_ID + "_private.key";
	private static final String BOB_PUBLIC_KEY_PATH = "resources/" + BOB_ID + "_public.key";
	private static final String ALICE_PUBLIC_KEY_PATH = "resources/" + "A" + "_public.key";
	private DiffieHellman dh;
	private String Ra;
	private String Rb;
	private String t;
	private Key Kmac;
	private SecretKey secKey;


	public Bob() throws Exception {
		this.ini = new IniManager();
		this.ssocket = new ServerSocket(ini.getBobServerPort());
		RSAProvider.RSAKeyGenerator(BOB_PRIVATE_KEY_PATH, BOB_PUBLIC_KEY_PATH, ini.getKeystorePass());
	}

	
	public void run() {
		Socket generalSocket;
		try {
			//RECEIVE CONNECTION
			generalSocket = ssocket.accept();
			ObjectOutputStream ObjectOutputStream = new ObjectOutputStream(generalSocket.getOutputStream());
			ObjectInputStream ObjectInputStream = new ObjectInputStream(generalSocket.getInputStream());

			//RECEIVE g, p AND key
			keyEncapsulationK(ObjectOutputStream, ObjectInputStream);
			sigMAauthentication(ObjectOutputStream, ObjectInputStream);
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void keyEncapsulationK(ObjectOutputStream oos, ObjectInputStream ois) throws Exception {
		Object [] object = (Object[]) ois.readObject();
		byte[] p = (byte[]) object[0];
		byte[] g = (byte[]) object[1];
		this.dh = new DiffieHellman(new BigInteger(p), new BigInteger(g));
		byte [] myDHPubKey = this.dh.getPublicKey().getEncoded();
		oos.writeObject(myDHPubKey);
		
		PublicKey alicePubKey = DiffieHellman.generatePublicKey((byte[]) object[2]);
		this.secKey = (SecretKey) this.dh.agreeSecretKey(alicePubKey, true);
		this.t = "(" + alicePubKey.hashCode() + "," + this.dh.getPublicKey().hashCode() +")";
		this.Kmac = SigMAuthentication.generateKmac(secKey, alicePubKey, this.dh.getPublicKey());	
	}
	
	public void sigMAauthentication(ObjectOutputStream oos, ObjectInputStream ois) throws Exception {
		Ra = new String((byte[]) ois.readObject(), StandardCharsets.UTF_8); ;
		Rb = binNumber();
		String message = "0"+ this.t + Ra + Rb;
		System.out.println(message);
		byte[] Bsig = SigMAuthentication.Sig(BOB_PRIVATE_KEY_PATH, message);
		message = "0" + BOB_ID;
		byte[] BMac = SigMAuthentication.MAC(this.Kmac, message);
		Object [] object = {BOB_ID, Rb, Bsig, BMac};
		oos.writeObject(object);
	
		//RECEIVE
		Object [] received = (Object[]) ois.readObject();
		String aliceID = (String) received[0];
		byte [] Asig = (byte[]) object[1];
		byte [] Amac = (byte[]) object[2];

		//VERIFICATION
		message = "1" + this.t + Ra + Rb;
		if(SigMAuthentication.SVF(ALICE_PUBLIC_KEY_PATH, message, Asig)) { //IF == 0 => true
			message = "1" + aliceID;
			
			if(SigMAuthentication.MVF(this.Kmac, message, Amac)) {
				
				String sid = "(" + t + "," + Ra + "," + Rb + "," + aliceID + "," + BOB_ID + ")";
				Key K = SigMAuthentication.KeyDerivationFunction(this.secKey, "KE" + sid);
				System.out.println("agreed key: " + new String(K.getEncoded()));
			
			}else throw new Exception("Alice's mac didn't hold");	
		}else throw new Exception("Alice's signature didn't hold");
	}
	
	public  String binNumber() {
	    Random rg = new Random();
	    int n = rg.nextInt(10);
	    return Integer.toBinaryString(n);
	}

	public static void main(String[] args) {

	}

}
