import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

public class EncDec {
    private static byte[] h2b(String hex){
        return DatatypeConverter.parseHexBinary(hex);
    }
    private static String b2h(byte[] bytes){
        return DatatypeConverter.printHexBinary(bytes);
    }

    private static SecureRandom sr = new SecureRandom();

    public KeyPair newKeyPair(int rsabits) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(rsabits, sr);
        return generator.generateKeyPair();
    }

    public static byte[] pubKeyToBytes(PublicKey key){
        return key.getEncoded(); // X509 for a public key
    }
    public static byte[] privKeyToBytes(PrivateKey key){
        return key.getEncoded(); // PKCS8 for a private key
    }

    public PublicKey bytesToPubKey(byte[] bytes) throws InvalidKeySpecException, NoSuchAlgorithmException{
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }
    public static PrivateKey bytesToPrivKey(byte[] bytes) throws InvalidKeySpecException, NoSuchAlgorithmException{
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public byte[] encryptWithPubKey(byte[] input, PublicKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    
    public byte[] encryptWithPriKey(byte[] input, PrivateKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    
    public byte[] decryptWithPrivKey(byte[] input, PrivateKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    
    public byte[] decryptWithPubKey(byte[] input, PublicKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }


    public String nonce_generator() throws NoSuchAlgorithmException
    {
    	
			   SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			  // byte[] bytes = new byte[1024/8];
			  // sr.nextBytes(bytes);
			   int seedByteCount = 2;
			   byte[] seed = sr.generateSeed(seedByteCount);
			   sr.setSeed(seed);
			   return String.valueOf(sr.nextInt(20));
    }
    
    public byte[] signature_generator(byte[] message,PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		
			Signature sig = Signature.getInstance("MD5WithRSA");
			sig.initSign(key);
			sig.update(message);
			return sig.sign();
	}
    
    public boolean verify_signature(byte[] message,byte[] signature,PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initVerify(key);
		sig.update(message);
		
		return sig.verify(signature);
	}
    
    public static void main(String[] args) throws Exception {
    	
    	EncDec encdec = new EncDec(); 
        KeyPair kp = encdec.newKeyPair(1<<10); // 1024 bit RSA; might take a second to generate keys
        PublicKey pubKey = kp.getPublic();
        PrivateKey privKey = kp.getPrivate();
        System.out.println(pubKey);
        System.out.println(privKey);
        String plainText = "2||HELLO||SESSION-KEY";
        byte[] cipherText = encdec.encryptWithPubKey(plainText.getBytes("UTF-8"),pubKey);
        System.out.println("cipherText: "+b2h(cipherText));
        System.out.println("plainText:");
        String plain_text= new String(encdec.decryptWithPrivKey(cipherText,privKey),"UTF-8"); 
        System.out.println(plain_text.trim());
        String[] array = plain_text.trim().split("\\|\\|");
        
        System.out.println(Integer.parseInt(array[0]));
    }
    
}

class DesEncrypter {
	  Cipher ecipher;
	  Cipher dcipher;
	  //static byte[] iv = null;
	  //  byte[] iv = {59, -109, -11, -22, -3, -121, -86, 31, 103, -18, 71, -2, -46, 68, 91, 123};
	  SecureRandom random = new SecureRandom();
	  /*
	  static protected void setIV()
	  {
		  SecureRandom random = new SecureRandom();
		  iv = new byte[16];
		  random.nextBytes(iv);
	  }
	  
	  static protected byte[] getIV()
	  {
		  return iv;
	  }
	 */ 
	  DesEncrypter(SecretKey key, byte[] iv) throws Exception {
	    ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
	    ecipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
	    dcipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
	    
	  }

	  @SuppressWarnings("restriction")
	public String encrypt(String str) throws Exception {
	    // Encode the string into bytes using utf-8
	    byte[] utf8 = str.getBytes("UTF8");

	    // Encrypt
	    byte[] enc = ecipher.doFinal(utf8);

	    // Encode bytes to base64 to get a string
	     
	    return new sun.misc.BASE64Encoder().encode(enc);
	    
	    
	    
	    
	  }

	  public String decrypt(String str) throws Exception {
	    // Decode base64 to get bytes
	    @SuppressWarnings("restriction")
		byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);

	    byte[] utf8 = dcipher.doFinal(dec);

	    // Decode using utf-8
	    return new String(utf8, "UTF8");
	  }
	}