package auth;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import org.ini4j.InvalidFileFormatException;

import general.IniManager;

public class Bob extends Thread {
	
	private IniManager ini;
	private ServerSocket ssocket;


	public Bob() throws InvalidFileFormatException, IOException {
		this.ini = new IniManager();
		this.ssocket = new ServerSocket(ini.getBobServerPort());
	}

	
	public void run() {
		Socket generalSocket;
		try {
			//RECEIVE CONNECTION
			generalSocket = ssocket.accept();
			ObjectOutputStream ObjectOutputStream = new ObjectOutputStream(generalSocket.getOutputStream());
			ObjectInputStream ObjectInputStream = new ObjectInputStream(generalSocket.getInputStream());
			
			
			keyEncapsulationK(ObjectOutputStream, ObjectInputStream);
			sigMAauthentication();
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	public void keyEncapsulationK(ObjectOutputStream oos, ObjectInputStream ois) throws IOException, ClassNotFoundException {
		//RECEIVE FROM ALICE
		Object [] received = (Object[]) ois.readObject();
		//SEND TO ALICE
		Object [] send = {"...", "..."};
		oos.writeObject(send);
	}
	
	public void sigMAauthentication() {
		//(...)
	}

	public static void main(String[] args) {

	}

}
