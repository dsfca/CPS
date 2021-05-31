package crypto;


import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import general.IniManager;



public class RSAProvider {

	private static final String ASSYMMETRIC_CYPHER_ALGO = "RSA";
	final static String DIGEST_ALGO = "SHA-256";
	
	/**************************************************************************************
	 * 											-RSAKeyGenerator()
	 * - generate rsa random pair(private and public) key and write them
	 *   in path passed as argument(rpivKeyPath and pubKeyPath) 
	 * 
	 * - input: 
	 * 		- privKeyPath: path to store generated private key.
	 * 		- pubKeyPath: path to story generayted public key.
	 * 
	 * - return:
	 * 
	 * ************************************************************************************/
public static void RSAKeyGenerator(String privKeyPath, String pubKeyPath, String password) throws Exception {
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASSYMMETRIC_CYPHER_ALGO);
        keyGen.initialize(1024);
        KeyPair keys = keyGen.generateKeyPair();
        
        PrivateKey privKey = keys.getPrivate();
        //byte[] privKeyEncoded = privKey.getEncoded();
        
        PublicKey pubKey = keys.getPublic();
        //byte[] pubKeyEncoded = pubKey.getEncoded();
        
        KeyFactory keyfactory = KeyFactory.getInstance(ASSYMMETRIC_CYPHER_ALGO);
        RSAPublicKeySpec rsaPubKeySpec = keyfactory.getKeySpec(pubKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec rsaPriKeySpec = keyfactory.getKeySpec(privKey, RSAPrivateKeySpec.class);
        
        saveKeys(pubKeyPath, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
        
        savePrivateKey(privKeyPath, rsaPriKeySpec.getModulus(), rsaPriKeySpec.getPrivateExponent(), password);
        
	}
	
	private static void saveKeys(String path, BigInteger modulus, BigInteger exp) throws Exception {
		FileOutputStream fos  = new FileOutputStream(path);
		ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(fos));
		oos.writeObject(modulus);
		oos.writeObject(exp);
		oos.close();
		fos.close();	
	}
	
	private static void savePrivateKey(String path, BigInteger modulus, BigInteger exp, String password) throws Exception {
		Key key = AESProvider.generateSecretKey(password);
		byte[] modulusCipher = AESProvider.AESCipherDecipher(key, modulus.toByteArray(), Cipher.ENCRYPT_MODE);
		byte[] expCipher = AESProvider.AESCipherDecipher(key, exp.toByteArray(), Cipher.ENCRYPT_MODE);
		FileOutputStream fos  = new FileOutputStream(path);
		ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(fos));
		oos.writeObject(modulusCipher);
		oos.writeObject(expCipher);
		oos.close();
		fos.close();
	}
	
	public static PublicKey readpublicKeyFromFile(String pubKeyPath) throws Exception {
		FileInputStream fis = new FileInputStream(new File(pubKeyPath));
		ObjectInputStream ois = new ObjectInputStream(fis);
		BigInteger mod = (BigInteger) ois.readObject();
		BigInteger exp = (BigInteger) ois.readObject();
		RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(mod, exp);
		KeyFactory fact = KeyFactory.getInstance(ASSYMMETRIC_CYPHER_ALGO);
		PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
		return publicKey;
		
	}
	
	public static PrivateKey readprivateKeyFromFile(String privKeyPath, String password) throws Exception {
		Key key = AESProvider.generateSecretKey(password);
		FileInputStream fis = new FileInputStream(new File(privKeyPath));
		ObjectInputStream ois = new ObjectInputStream(fis);
		byte[] modulusCipher = (byte[]) ois.readObject();
		byte[] expCipher = (byte[]) ois.readObject();
		byte[] modbyte = AESProvider.AESCipherDecipher(key, modulusCipher, Cipher.DECRYPT_MODE);
		byte[] extbyte = AESProvider.AESCipherDecipher(key, expCipher, Cipher.DECRYPT_MODE);
		BigInteger mod = new BigInteger(modbyte);
		BigInteger exp = new BigInteger(extbyte);
		RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(mod, exp);
		KeyFactory fact = KeyFactory.getInstance(ASSYMMETRIC_CYPHER_ALGO);
		PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
		return privateKey;
		
	}
	
	/**write content of the array 
	 * content and save it on a given path
	 */
	public static void write(byte[] content, String path) throws Exception {
		FileOutputStream file  = new FileOutputStream(path);
        file.write(content);
        file.close();
	}
	

	/**************************************************************************************
	 * 											-readRSAKey()
	 * - return rsa key pair(private and public) readed from files with paths passed 
	 * 	 in argument. The keys must be previously generated and related 
	 * 
	 * - input: 
	 * 		- pubKeyPath: public key path 
	 * 		- privKeyPath: private key path
	 * 
	 * - return rsa key pair 
	 * 
	 * ************************************************************************************/
	public static KeyPair readRSAKey(String pubkeypath, String privKeyPath, String PrivKeyPassword) throws Exception {
	    PublicKey pub = readpublicKeyFromFile(pubkeypath);	    
        PrivateKey priv = readprivateKeyFromFile(privKeyPath, PrivKeyPassword);
        KeyPair keys = new KeyPair(pub, priv);
        return keys;
	}
	
	
	public static byte[] signe(PrivateKey key, byte[] content ) throws Exception {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); 
		byte[] hash = sha256.digest(content);
		Cipher cipher = Cipher.getInstance(ASSYMMETRIC_CYPHER_ALGO);
    	cipher.init(Cipher.ENCRYPT_MODE, key);
    	byte[] messageCyphered = cipher.doFinal(hash);
    	return messageCyphered;
	}
	
	public static byte[] unsigne(PublicKey key, byte[] singnature) throws Exception {
		Cipher cipher = Cipher.getInstance(ASSYMMETRIC_CYPHER_ALGO);
    	cipher.init(Cipher.ENCRYPT_MODE, key);
    	byte[] content = cipher.doFinal(singnature);
    	return content;
	}
	
	
	
	public static byte[] readfile(String path) throws Exception {
		FileInputStream file = new FileInputStream(path);
        byte[] fileEncoded = new byte[file.available()];
        file.read(fileEncoded);
        file.close();
        return fileEncoded;
	}
	
	
	/**************************************************************************************
	 * 											-getTexthashEnWithPriKey()
	 * 
	 * - return plain text hash cyphered with private key, important when processing 
	 * 	 the digital signature of a text. the text returned is encoded on base 64.
	 * 
	 * - input: 
	 * 		- plaintext: plain text whose hash will be generated and encrypted with private key
	 * 		- key: private key to cypher hash of plain text.
	 * 
	 * - return: hash of plain text encrypted with private key(encoded on base 64)
	 * 
	 * ************************************************************************************/
	public static String getTexthashEnWithPriKey(String plaintext, PrivateKey key) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);
        messageDigest.update(plaintext.getBytes());
        byte[] digestBytes = messageDigest.digest();
        String digestB64dString = Base64.getEncoder().encodeToString(digestBytes);
        String digestCyphered = priKeyCiphDeciph(digestB64dString, key, Cipher.ENCRYPT_MODE);
        return digestCyphered;
	}
	
	/**************************************************************************************
	 * 											-istextAuthentic()
	 * 
	 * - verify the digital signature of the plaintext and return true 
	 * 	 if signature is valid and false otherwise.
	 * 	 computes hash of the plaintext, decipher the plaintext hash ciphered with private key(digesCiphered)
	 * 	 and verify if both are equals.
	 *  
	 * 
	 * - input: 
	 * 		- plaintext: plain text to valid the digital signature
	 * 		- digesCiphered: supposed hash of plaintext ciphered with private key.
	 * 		- key: public key of private key used to cipher digesCiphered.
	 * 
	 * - return: boolean( true if signature is valid, false otherwise)
	 * ************************************************************************************/
	public static boolean istextAuthentic(String plaintext ,String digesCiphered, PublicKey key)throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);
        messageDigest.update(plaintext.getBytes());
        byte[] digestBytes = messageDigest.digest();
        String digestB64dString = Base64.getEncoder().encodeToString(digestBytes);
		String digesCipheredtB64dString = pubKeyCiphDeciph(digesCiphered, key, Cipher.DECRYPT_MODE );
		return digesCipheredtB64dString.equals(digestB64dString);
	}
	
	
	/**************************************************************************************
	 * 											-priKeyCiphDeciph()
	 * 
	 * - cipher or decipher text (message_B64) depending on cipher mode passed in
	 * 	 argument(mode) with private key passed(key) and return the result encoded in base64.
	 * 
	 * - input: 
	 * 		- message_B64: text encoded on base64
	 * 		- key: private key to cipher or decipher message_B64.
	 * 		- mode: cipher mode(cipher or decipher)
	 * 
	 * - return: string encoded in base64
	 * 
	 * 
	 * ************************************************************************************/
	public static String priKeyCiphDeciph(String message_B64, PrivateKey key, int mode ) throws Exception {
		byte[] messageBytes = Base64.getDecoder().decode(message_B64);
    	Cipher cipher = Cipher.getInstance(ASSYMMETRIC_CYPHER_ALGO);
    	cipher.init(mode, key);
    	byte[] messageCyphered = cipher.doFinal(messageBytes);
    	String cipherB64String = Base64.getEncoder().encodeToString(messageCyphered);
    	return cipherB64String;
	}
	
	/**************************************************************************************
	 * 											-pubKeyCiphDeciph()
	 * 
	 * - cipher or decipher text (message_B64) depending on cipher mode passed in
	 * 	 argument(mode) with public key passed(key) and return the result encoded in base64.
	 * 
	 * - input: 
	 * 		- message_B64: text encoded on base64
	 * 		- key: public key to cipher or decipher message_B64.
	 * 		- mode: cipher mode(cipher or decipher)
	 * 
	 * - return: string encoded in base64
	 * 
	 * 
	 * ************************************************************************************/
	public static String pubKeyCiphDeciph(String message_B64, PublicKey key, int mode ) throws Exception {
		byte[] messageBytes = Base64.getDecoder().decode(message_B64);
    	Cipher cipher = Cipher.getInstance(ASSYMMETRIC_CYPHER_ALGO);
    	cipher.init(mode, key);
    	byte[] messageCyphered = cipher.doFinal(messageBytes);
    	String cipherB64String = Base64.getEncoder().encodeToString(messageCyphered);
    	return cipherB64String;
	}
	
	/*public static void main(String[] args) {
		
		try {
			IniManager ini = new IniManager();
			//for(int i = 0; i < 10; i++) {
				String privKeyPath = "resources/A_private.key";
				String pubKeyPath = "resources/A_public.key";
				RSAKeyGenerator(privKeyPath, pubKeyPath, ini.getKeystorePass());
				
			
			//}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}*/
	
}
