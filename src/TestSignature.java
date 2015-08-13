import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import sun.misc.BASE64Encoder;

public class TestSignature {
	
	public static byte[] signature_generator(byte[] message,PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		
			Signature sig = Signature.getInstance("MD5WithRSA");
			sig.initSign(key);
			sig.update(message);
			return sig.sign();
	}
	
	public static boolean verify_signature(byte[] message,byte[] signature,PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initVerify(key);
		sig.update(message);
		
		return sig.verify(signature);
	}
	
	public static void main(String[] argv) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	    kpg.initialize(1024);
	    KeyPair keyPair = kpg.genKeyPair();
	    
	    String testmessage = "hello world";
	    byte[] data = testmessage.getBytes();
	    byte[] signature = signature_generator(data, keyPair.getPrivate());
	    
	    boolean verify = verify_signature(data, signature, keyPair.getPublic());
	    
	    System.out.println("digital signature is :" + verify);
		
	}

}