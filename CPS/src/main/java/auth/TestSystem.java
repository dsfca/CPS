package auth;

import java.io.IOException;

import org.ini4j.InvalidFileFormatException;

public class TestSystem {

	public TestSystem() {
		
	}

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();
		bob.start();
		//Alice alice = new Alice();
		//alice.start();
	}

}
