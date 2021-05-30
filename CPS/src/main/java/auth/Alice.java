package auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import org.ini4j.InvalidFileFormatException;

import general.IniManager;

public class Alice extends Thread{
	
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
		}
	}

	public void keyEncapsulationK() throws IOException, ClassNotFoundException {
		//CREATE OBJECT AND THEN SEND TO BOB
		Object [] object = {"..."};
		this.bobObjectOutputStream.writeObject(object);
		//RECEIVE FROM BOB
		Object [] received = (Object[]) this.bobObjectInputStream.readObject();
		//(...)
	}

	public void sigMAauthentication() {

	}

	public static void main(String[] args) {

	}

}
