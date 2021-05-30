package auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.PublicKey;

import org.ini4j.InvalidFileFormatException;

import crypto.DiffieHelman;
import general.IniManager;

public class Alice extends Thread{
	private static final String ALICE_PRIVATE_KEY_PATH = "";
	private static final String ALICE_ID = "A";
	private DiffieHelman DH;
	private String Ra;
	private String Rb;
	private String t;
	private Key Kmac;
	private Key k;
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
		this.k = this.DH.agreeSecretKey(BobPubKey, true);
	}

	public void sigMAauthentication() {
		
	}

	public static void main(String[] args) {

	}

}
