package crypto;

import java.security.MessageDigest;
import java.security.PrivateKey;

import java.security.Key;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SigMAuthentication {
	private static String password = "cps";
	private static final String DIGEST_ALG = "SHA-256";
	private static final String SYMMETRIC_CYPHER_ALGO = "AES";
	
	
	/**************************************************************************************
	 * 											-Sig()
	 * - Signature: signs the message passed as argument.
	 * 
	 * input:
	 * 			privateKeyPath: path of the signer private key
	 * 			message: message to sign
	 * 
	 * - return array of byte.
	 * 
	 * ************************************************************************************/
	public static byte[] Sig(String privateKeyPath, String message  ) throws Exception {
		PrivateKey prvkey = RSAProvider.readprivateKeyFromFile(privateKeyPath, password);
		byte[] message_sig = RSAProvider.signe(prvkey, message.getBytes());
		return message_sig;
	}
	
	/**************************************************************************************
	 * 											-MAC()
	 * - MAC(Message Authentication Code): cipher the message with Kmac and returns 
	 * 	 the digest of the cipher message
	 *  
	 * input:
	 * 			secretKey:secret key to cipher the message
	 * 			message: message to cipher
	 * 
	 * - return array of byte.
	 * 
	 * ************************************************************************************/
	public static byte[] MAC(SecretKey Kmac, String message) throws Exception {
		MessageDigest sha256 = MessageDigest.getInstance(DIGEST_ALG); 
		byte[] messageCiphered = AESProvider.AESCipherDecipher(Kmac, message.getBytes(), Cipher.ENCRYPT_MODE);
		byte[] messageMac = sha256.digest(messageCiphered);
		return messageMac;
	}
	
	/**************************************************************************************
	 * 											-SVF()
	 * - SVF(Signature Verification function) verifies if the sig  is equal to opponent 
	 * signature  
	 * 
	 * input:
	 * 			pubKeyPath: opponent public key path.
	 * 			message: message to verify if its signature is equal to opponent signature
	 * 			sig: opponent sig.
	 * 
	 * - return boolean(true or false)
	 * 
	 * ************************************************************************************/
	public static boolean SVF(String pubKeyPath, String message, byte[] sig) throws Exception {
		PublicKey pubKey = RSAProvider.readpublicKeyFromFile(pubKeyPath);
		byte[] opponent_sig = RSAProvider.unsigne(pubKey, sig);
		MessageDigest sha256 = MessageDigest.getInstance(DIGEST_ALG);
		byte[] messageMac = sha256.digest(message.getBytes());
		String oppenentMacStr = new String(opponent_sig);
		String messageMacStr = new String(messageMac);
		return oppenentMacStr.equals(messageMacStr);
	}
	
	
	/**************************************************************************************
	 * 											-MVF()
	 * - MVF(Mac Verification function) verifies if the given mac is equal to mac 
	 * 	of the message.
	 * 
	 * input:
	 * 			kmac: key used by opponent to cipher mac.
	 * 			message: message to digest and verify if it's equal mac
	 * 			mac: opponent mac.
	 * 
	 * - return boolean(true or false)
	 * 
	 * ************************************************************************************/
	public static boolean MVF(SecretKey kmac, String message, byte[] mac) throws Exception {
		byte[] messageMAC = MAC(kmac, message);
		String oppenentMacStr = new String(mac);
		String messageMacStr = new String(messageMAC);
		return messageMacStr.equals(oppenentMacStr);
	}
	
	/**************************************************************************************
	 * 											-KeyDerivationFunction()
	 * - derives a key given a secret key between two entities and a sid(security identifier).
	 * 	 cipher the sid with secret key, hash the result and generate the key.
	 * 
	 * input:
	 * 			sk: secret key between two entities
	 * 			sid: security identifier.
	 * 
	 * - return the generated key.
	 * 
	 * ************************************************************************************/
	public static Key KeyDerivationFunction(SecretKey sk, String sid) throws Exception {
		byte[] cipherPass = AESProvider.AESCipherDecipher(sk, sid.getBytes(), Cipher.ENCRYPT_MODE);
		MessageDigest sha256 = MessageDigest.getInstance(DIGEST_ALG);
		byte[] macipherPass = sha256.digest(cipherPass);
		SecretKeySpec key = new SecretKeySpec(macipherPass, SYMMETRIC_CYPHER_ALGO);
		return key;
	}
}