package crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class DiffieHelman {
	private static final int AES_KEY_SIZE = 128;
	
	private KeyPair keyPair;
	private BigInteger p;
	private BigInteger g;
	
	
	public DiffieHelman() {
		try {
			init();
		} catch (Exception e) {
			e.printStackTrace();
		}  
	}
	
	public DiffieHelman(BigInteger p, BigInteger g) {
		try {
			init(p,g);
			this.p = p;
			this.g= g;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void init() throws Exception {
		 AlgorithmParameterGenerator paramGen;
		 paramGen = AlgorithmParameterGenerator.getInstance("DH");
		 paramGen.init(512);
		 AlgorithmParameters params = paramGen.generateParameters();
		 DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
		 keyGen.initialize(dhSpec);
		 keyPair = keyGen.generateKeyPair();
		 p = dhSpec.getP();
		 g = dhSpec.getG();
	}
	
	public BigInteger getP() {
		return p;
	}
	
	public BigInteger getG() {
		return g;
	}
	public void init(BigInteger p, BigInteger g) throws Exception {
		 KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
		 DHParameterSpec param = new DHParameterSpec(p,g);
		 kpg.initialize(param);
		 keyPair = kpg.generateKeyPair();
	}
	
	public PublicKey getPublicKey() {
		return keyPair.getPublic();
	}
	
	
	
	public Key agreeSecretKey(PublicKey pbk, boolean lastPhase) throws Exception {
		PrivateKey myPrk = keyPair.getPrivate();
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(myPrk);
		ka.doPhase(pbk, lastPhase);
		byte[] secret = ka.generateSecret();
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); 
        byte[] bkey = Arrays.copyOf(
                sha256.digest(secret), AES_KEY_SIZE / Byte.SIZE);
        SecretKeySpec key = new SecretKeySpec(bkey, "AES");
        return key;
	}
	
	public static PublicKey generatePublicKey(byte[] publicKeyContent) throws Exception {
		//Convert SubjectPublicKeyInfo ASN.1 format to java public key format
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyContent);
		KeyFactory keyFacPub = KeyFactory.getInstance("DH");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
	}
	
/*	public static BInteger write(BigInteger val) {
		
		   BInteger.Builder builder = BInteger.newBuilder();
		    ByteString bytes = ByteString.copyFrom(val.toByteArray());
		    builder.setValue(bytes);
		    return builder.build();
		  }

	public static BigInteger read(BInteger message) {
		 ByteString bytes = message.getValue();
		 return new BigInteger(bytes.toByteArray());
	}*/

}
