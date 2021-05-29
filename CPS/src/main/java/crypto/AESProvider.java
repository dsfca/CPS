package crypto;

import java.io.FileInputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESProvider {
	
	private static final String SYMMETRIC_CYPHER_ALGO = "AES";
	private static final int KEY_DERIVATION_ITERACTION = 65536;
	private static final int AES_KEY_SIZE = 128;

	/**************************************************************************************
	 * 											-AESKeyGenerator()
	 * - use bouncy castle provider to generate AES random key.
	 * 
	 * - return the generated key.
	 * 
	 * ************************************************************************************/
	public static Key AESKeyGenerator() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_CYPHER_ALGO, "BC");
        keyGen.init(128);
        Key key = keyGen.generateKey();
        return key;
	}
	
	/**************************************************************************************
	 * 											-generateSecretKey()
	 * - generates aes secret key given a password, compute the hash of the password and then
	 * 		use it to create secret key	
	 * 
	 * - input:
	 * 		- password : secret key password
	 * 
	 *- return: final result text by applying key and operation mode encoded in base64
	 * 
	 * ************************************************************************************/
	public static Key generateSecretKey(String password) throws Exception {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); 
        byte[] bkey = Arrays.copyOf(
                sha256.digest(password.getBytes()), AES_KEY_SIZE / Byte.SIZE);
        SecretKeySpec key = new SecretKeySpec(bkey, "AES");
        return key;
	}
	
	/**************************************************************************************
	 * 											-AESCypherDecypher()
	 * -	Depending on operation mode given, cypher or decypher the base64 
	 * 		text passed as argument with key "key" using aes algorithm 
	 * 		and return result encode on base64 
	 * 
	 * - input:
	 * 		- key: key to cypher or decypher text
	 * 		-text: pretended text to cypher or decypher
	 * 		mode: operation mode(cypher or decypher)
	 * 
	 *- return: final result text by applying key and operation mode encoded in base64
	 * 
	 * ************************************************************************************/
	public static String AESCypherDecypher( Key key, String text, int mode) throws Exception {
		byte[] messageBytes = Base64.getDecoder().decode(text);
    	Cipher cipher = Cipher.getInstance(SYMMETRIC_CYPHER_ALGO);
    	cipher.init(mode, key);
    	byte[] messageCyphered = cipher.doFinal(messageBytes);
    	String cipherB64String = Base64.getEncoder().encodeToString(messageCyphered);
    	return cipherB64String;
	}
	
	
	public static byte[] AESCipherDecipher( Key key, byte[] content, int mode) throws Exception {
		Cipher cipher = Cipher.getInstance(SYMMETRIC_CYPHER_ALGO);
    	cipher.init(mode, key);
    	byte[] result = cipher.doFinal(content);
    	return result;
	}
	
	/**************************************************************************************
	 * 											-getCipherOfPlainText()
	 * - return the encrypted text(encoded on base64) of plain text with
	 * 	 aeskey passed as argument. This function is similar to AESCypherDecypher function above, 
	 * 	 except that the text received as argument(plainText) is not encoded on base64).
	 * 
	 * - input:
	 * 		-plaintext: the desired plaint text to encrypt(not encoded on base64)
	 * 		-aeskey: the key used to encrypt plaintext.
	 *
	 * - return: the plaintext encrypted with key "aeskey" on base64.
	 * 
	 * ************************************************************************************/
	public static String getCipherOfPlainText(String plaintext, Key aeskey) throws Exception {
		byte[] plaintextbytes = plaintext.getBytes();
        String encodedString = Base64.getEncoder().encodeToString(plaintextbytes);
        String cipherTextEncoded =AESCypherDecypher(aeskey, encodedString, Cipher.ENCRYPT_MODE);
        return cipherTextEncoded;
	}
	
	
	/**************************************************************************************
	 * 											-getPlainTextOfCipherText()
	 * - return the plaint text result from decrypting the cypher text passed 
	 * 	 in the argument with key "aeskey". this function is opposite
	 * 	 of fuction above(getCipherOfPlainText)
	 * 
	 * - input:
	 * 		-cyphertext: the desired cypher text to decrypt(encoded on base64)
	 * 		-aeskey: the key used to encrypt plaintext that produced the cyphertext.
	 *
	 * - return: the plain text of cypher text encrypted with key "aeskey".
	 * 
	 * ************************************************************************************/
	public static String getPlainTextOfCipherText(String cipherText, Key aeskey) throws Exception {
		String plaintextEncoded = AESCypherDecypher(aeskey, cipherText, Cipher.DECRYPT_MODE);
		byte[] decodedBytes = Base64.getDecoder().decode(plaintextEncoded);
		return new String(decodedBytes);
	}
	
	/**************************************************************************************
	 * 											-readAESKey()
	 * - read aes key file with path keyPath and returns it as object key.
	 * 
	 * - input:
	 * 		-keyPath: path that contain aes key to be readed
	 *
	 * - return: readed aes key.
	 * 
	 * ************************************************************************************/
	public static Key readAESKey(String keyPath) throws Exception {
		FileInputStream fis = new FileInputStream(keyPath);
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();
        return new SecretKeySpec(encoded , 0, 16, "AES");
	}
	
	
	
	
	
	
	
	
	
	
	/*public static void main(String[] args) {	
		try {
			String sharedKeyPath = "shared/sharedAESKey.key";
			Key key;
			key = AESKeyGenerator();
			byte[] encoded = key.getEncoded();
			RSAProvider.write(encoded, sharedKeyPath);
			System.out.println("key stored at : " + sharedKeyPath);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}*/
	
	
	
	
	
	
}
