package crypto;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class SigMAuthentication {
	private static String password = "cps";
	private static final String DIGEST_ALG = "SHA-256";
	
	
	public static byte[] Sig(String privateKeyPath, String message  ) throws Exception {
		PrivateKey prvkey = RSAProvider.readprivateKeyFromFile(privateKeyPath, password);
		byte[] message_sig = RSAProvider.signe(prvkey, message.getBytes());
		return message_sig;
	}
	
	public static byte[] MAC(SecretKey Kmac, String message) throws Exception {
		MessageDigest sha256 = MessageDigest.getInstance(DIGEST_ALG); 
		byte[] messageCiphered = AESProvider.AESCipherDecipher(Kmac, message.getBytes(), Cipher.ENCRYPT_MODE);
		byte[] messageMac = sha256.digest(messageCiphered);
		return messageMac;
	}
	
	/**
	 * Signature Verification Function
	 * @throws Exception 
	 * */
	public static boolean SVF(String pubKeyPath, String message, byte[] sig) throws Exception {
		PublicKey pubKey = RSAProvider.readpublicKeyFromFile(pubKeyPath);
		byte[] opponent_sig = RSAProvider.unsigne(pubKey, sig);
		MessageDigest sha256 = MessageDigest.getInstance(DIGEST_ALG);
		byte[] messageMac = sha256.digest(message.getBytes());
		String oppenentMacStr = new String(opponent_sig);
		String messageMacStr = new String(messageMac);
		return oppenentMacStr.equals(messageMacStr);
	}
	
	
	/**
	 * Mac Verification Function
	 * @throws Exception 
	 * */
	public static boolean MVF(SecretKey kmac, String message, byte[] mac) throws Exception {
		byte[] messageMAC = MAC(kmac, message);
		String oppenentMacStr = new String(mac);
		String messageMacStr = new String(messageMAC);
		return messageMacStr.equals(oppenentMacStr);
	}
	 
}
