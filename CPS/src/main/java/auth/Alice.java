package auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Random;

import javax.crypto.SecretKey;

import org.ini4j.InvalidFileFormatException;

import crypto.DiffieHelman;
import crypto.SigMAuthentication;
import general.IniManager;

public class Alice extends Thread{
	private static final String ALICE_PRIVATE_KEY_PATH = "";
	private static final String BOB_PUBLIC_KEY_PATH = "";
	private static final String ALICE_ID = "A";
	private DiffieHelman DH;
	private String Ra;
	private String Rb;
	private String t;
	private Key Kmac;
	private SecretKey secKey;
	/*******************************************************************************************************************************************/
	private IniManager ini;
	private int client_port;
	
	private Socket bobSocket;
	private ObjectOutputStream bobObjectOutputStream;
	private ObjectInputStream bobObjectInputStream;
	

	public Alice() throws InvalidFileFormatException, IOException {
		this.ini = new IniManager();
		this.client_port = ini.getAliceClientPort();
		
		this.bobSocket = (Socket) new Socket(ini.getBobHost(), ini.getBobServerPort());
		this.bobObjectOutputStream = new ObjectOutputStream(bobSocket.getOutputStream());
		this.bobObjectInputStream = new ObjectInputStream(bobSocket.getInputStream());
		this.DH = new DiffieHelman();
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void keyEncapsulationK() throws Exception {
		byte[] p = this.DH.getP().toByteArray();
		byte[] g = this.DH.getG().toByteArray();
		byte[] myDHPubKey = this.DH.getPublicKey().getEncoded();
		//CREATE OBJECT AND THEN SEND TO BOB
		Object [] object = {p, g, myDHPubKey};
		this.bobObjectOutputStream.writeObject(object);
		//RECEIVE FROM BOB
		byte [] received = (byte[]) this.bobObjectInputStream.readObject();
		PublicKey BobPubKey = DiffieHelman.generatePublicKey(received);
		this.secKey = (SecretKey) this.DH.agreeSecretKey(BobPubKey, true);
		 t = "(" + this.DH.getPublicKey().hashCode() + "," + BobPubKey.hashCode() +")";
		this.Kmac = SigMAuthentication.generateKmac(secKey, this.DH.getPublicKey(), BobPubKey);
	}
	

	public void sigMAauthentication() throws Exception {
		Ra = binNumber();
		this.bobObjectOutputStream.writeObject(Ra.getBytes());
		
		Object [] received = (Object[]) this.bobObjectInputStream.readObject();
		String BobID = (String) received[0];
		Rb = (String) received[1];
		byte[] Bsigma = (byte[]) received[2];
		byte[] BMac = (byte[]) received[3];
		
		String message = "0||"+ t + "||" + Ra + "||" + Rb;
		if(SigMAuthentication.SVF(BOB_PUBLIC_KEY_PATH, message, Bsigma)) {
			message = "0||" + BobID;
			if(SigMAuthentication.MVF(this.Kmac, message, BMac)) {
				message = "1||"+ t + "||" + Ra + "||" + Rb;
				byte[] Asig = SigMAuthentication.Sig(ALICE_PRIVATE_KEY_PATH, message);
				message = "1||" + ALICE_ID;
				byte[] AMac = SigMAuthentication.MAC(Kmac, message);
				
				Object [] object = {ALICE_ID, Asig, AMac};
				this.bobObjectOutputStream.writeObject(object);
				
				String sid = "(" + t + "," + Ra + "," + Rb + "," + ALICE_ID + "," + BobID + ")";
				
				Key K= SigMAuthentication.KeyDerivationFunction(secKey, "KE||"+sid);
				
				System.out.println("agreed key: " + new String(K.getEncoded()));
				
			}else throw new Exception("bob mac didn't hold");
		}else throw new Exception("bob signature didn't hold");
		
	}
	
	public  String binNumber() {
	    Random rg = new Random();
	    int n = rg.nextInt(10);
	    return Integer.toBinaryString(n);
	}

	public static void main(String[] args) {

	}

}
