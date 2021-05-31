package general;

import java.io.File;
import java.io.IOException;

import org.ini4j.Ini;
import org.ini4j.InvalidFileFormatException;

public class IniManager {
	
	
	private Ini ini;

	
	public IniManager() throws InvalidFileFormatException, IOException {
		this.ini = new Ini(new File("parameters.ini"));
	}
	
	/**Alice**/
	public int getAliceClientPort() {
		return ini.get("Alice","client_port", Integer.class);
	}
	
	/**Bob**/
	public int getBobServerPort() {
		return ini.get("Bob","server_port", Integer.class);
	}

	public String getBobHost() {
		return ini.get("Bob","host", String.class);
	}
	
	/**General**/
	public String getKeystorePass() {
		return ini.get("general","password", String.class);
	}
	
	
	public static void main(String[] args) {

	}

}
