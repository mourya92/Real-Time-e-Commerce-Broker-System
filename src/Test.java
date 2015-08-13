import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.ObjectInputStream.GetField;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;



import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
 
@SuppressWarnings("restriction") 

class Test{
	
	static String[] keyList = new String[2];
	static BASE64Decoder decode_IncomingMessage = new BASE64Decoder();
	static PublicKey pubKey = null; 
	static PrivateKey privKey = null; 
    
	private static String getDigest(String encoded_Product_Selection) {
		// TODO Auto-generated method stub
		
		MessageDigest md;
		StringBuffer hexString = null; 
		try {
				md = MessageDigest.getInstance("MD5");
				md.update(encoded_Product_Selection.getBytes());

				byte byteData[] = md.digest();

				hexString = new StringBuffer();
				for (int j = 0; j < byteData.length; j++) {
					String hex = Integer.toHexString(0xff & byteData[j]);
					if (hex.length() == 1)
						hexString.append('0');
					hexString.append(hex);
				}
			
			}catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		
		return hexString.toString();
	}
	
	protected static String[] generate(){
 
        try {
        	String pubKeyFile = "Files/Broker_pub_key.txt";
            
        	// Create the public and private keys
        	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        	BASE64Encoder base64 = new BASE64Encoder();
            
        	generator.initialize(1024, new SecureRandom());
 
            KeyPair pair = generator.generateKeyPair();
            pubKey = pair.getPublic();
            privKey = pair.getPrivate();
            
            String test = "Hello World";
            
            //keyList[0] = (base64.encode(pubKey.getEncoded())); 
            //keyList[1] = base64.encode(privKey.getEncoded());
        
            //BufferedWriter out = new BufferedWriter(new FileWriter(pubKeyFile));
            FileOutputStream fos = new FileOutputStream(pubKeyFile);
            fos.write(pubKey.getEncoded());
            System.out.println("The publickey in string is :" + new String(pubKey.getEncoded()));
            System.out.println("size fo public key is" + pubKey.getEncoded().length);
            System.out.println("sizeof the bytes in the file is :" + pubKeyFile.length());
            fos.close();
            
            FileInputStream fis = new FileInputStream(pubKeyFile);
            DataInputStream dis = new DataInputStream(fis);
            
            Path path = Paths.get(pubKeyFile);
            byte[] keyBytes = null;
            
            keyBytes= Files.readAllBytes(path);
            
            System.out.println("the public key read from file is :"+new String(keyBytes));
            
            //byte[] publicBytes = keyList[0].getBytes();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey PubKey = keyFactory.generatePublic(keySpec);
            
            System.out.println(" STRING PUBLIC KEY : " + keyList[0]);
            System.out.println(" PUBLIC KEY : " + PubKey);
            
            
            EncDec encdec = new EncDec();
        	System.out.println(test.getBytes());
        	byte[] encrypt_text = encdec.encryptWithPubKey(test.getBytes(), PubKey); 
        	System.out.println(encrypt_text);
        	byte[] decrypt_text = encdec.decryptWithPrivKey(encrypt_text, privKey) ; 
        	System.out.println("DECRYPTED MESSAGE :" + new String(decrypt_text));
        	
        	 KeyGen keygen0 = new KeyGen(); 
        	 KeyGen keygen1 = new KeyGen(); 
        	 KeyGen keygen2 = new KeyGen(); 
        	 KeyGen keygen3 = new KeyGen(); 
        	 KeyPair pair0 = keygen0.generate("Client");
        	 KeyPair pair1 = keygen1.generate("Broker");
        	 KeyPair pair2 = keygen2.generate("Amazon");
        	 KeyPair pair3 = keygen3.generate("Ebay");
        	 
        	 System.out.println(keygen0.getPubKey("Broker"));
        	
        	
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return keyList;
		
    }
    
protected static SecretKey getSessionKey(){
    	
    	SecretKey sessionkey = null;
    	 
        try {
 
            // Create the public and private keys
        	 KeyGenerator generator = KeyGenerator.getInstance("DES");
        	 BASE64Encoder base64 = new BASE64Encoder();
 
        	generator.init(56,new SecureRandom());
            sessionkey = generator.generateKey();
 
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return sessionkey;
		
    }

public static void main(String[] argv) throws Exception {
	
	
	SecretKey SecKey = new KeyGen().getSessionKey(); 

    
    
	//byte[] data = sessionkey.getEncoded();

	EncDec encdec = new EncDec(); 
	
	String[] KeyArray = generate(); 
	
//	BASE64Encoder base64 = new BASE64Encoder();
//	byte[]   bytesEncoded = base64.encodeBase64(((String) sessionkey) .getBytes());
//	System.out.println("ecncoded value is " + new String(bytesEncoded ));
	
	String plaintext = "CHALLENGE"; 	
	
	System.out.println("*******************");
	
	System.out.println(SecKey.getAlgorithm() + SecKey.getEncoded().length);
	//DesEncrypter.setIV();
	
	SecureRandom random = new SecureRandom();
	  byte[] iv = new byte[16];
	  random.nextBytes(iv);
	  
	DesEncrypter desencrypter = new DesEncrypter(SecKey, iv); 
	System.out.println(plaintext);
	System.out.println(SecKey);
	System.out.println(SecKey.toString());
	String cipher = desencrypter.encrypt(plaintext); 
	System.out.println(cipher);
	DesEncrypter desencrypter1 = new DesEncrypter(SecKey, iv);
	System.out.println(desencrypter1.decrypt(cipher));
	
	System.out.println("*******************");
	
	System.out.println(plaintext.getBytes());
	byte[] encrypt_text = encdec.encryptWithPubKey(plaintext.getBytes(), pubKey); 
	System.out.println(encrypt_text);
	byte[] decrypt_text =  encdec.decryptWithPrivKey(encrypt_text, privKey) ; 
	System.out.println(new String(decrypt_text).trim());
	
	SecretKey SessionKey_Broker = getSessionKey(); 
	System.out.println("SESSION KEY SENT : " + SessionKey_Broker);
	
	DesEncrypter desencrypter_test = new DesEncrypter(SecKey, iv); 
	
	String ci = new String(); 
	ci = desencrypter_test.encrypt("mourya"); 
	
	System.out.println("TEST: "+ ci);
	
	byte[] sessionKey_Broker_byte = SessionKey_Broker.getEncoded();
	
//	SecretKey originalKey = new SecretKeySpec(sessionKey_Broker_byte, 0, sessionKey_Broker_byte.length, "DES");
//	
//	DesEncrypter desencrypter_test1 = new DesEncrypter(originalKey); 
//	System.out.println("TEST: "+ desencrypter_test1.decrypt(ci));
	
	
	
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	
	outputStream.write((Integer.toString(2)+("||")).getBytes());
	outputStream.write("CHALLENGE".getBytes());
	outputStream.write(("||").getBytes());			
	outputStream.write(sessionKey_Broker_byte);
	
	outputStream.toByteArray();
	
	System.out.println(outputStream.toByteArray());
	System.out.println(outputStream);
	
	BASE64Encoder base64 = new BASE64Encoder();
	
	System.out.println(new String((outputStream.toByteArray())));
	
	String str = base64.encode((outputStream.toByteArray()));
	
	byte[] b = decode_IncomingMessage.decodeBuffer(str);
	
	System.out.println(new String(b));
	
	String pubKeyFile = "Files/Amazon_pub_key.txt";
	String priKeyFile = "Files/Amazon_pri_key.txt";
	//User_PassFile = "User_Pass.txt";
	
	System.out.println(" BROKER PUBLIC KEY : CREATED");
	EncDec keygen = new EncDec();
	KeyPair pair = keygen.newKeyPair(1 << 11);
	PublicKey my_pub_key = pair.getPublic();
	PrivateKey my_private_key = pair.getPrivate();

	System.out.println(" BROKER PRIVATE KEY : CREATED");
	FileOutputStream key_writer = new FileOutputStream(pubKeyFile);
	key_writer.write(my_pub_key.getEncoded());
	key_writer.close();

	key_writer = new FileOutputStream(priKeyFile);
	key_writer.write(my_private_key.getEncoded());
	key_writer.close();

	Path path_Az = Paths.get("Files/Amazon_pub_key.txt");
	byte[] keyBytes_Az_pub = Files.readAllBytes(path_Az);

    PublicKey publicKey_WebServer = keygen.bytesToPubKey(keyBytes_Az_pub);
    
    Path path_Az_pri = Paths.get("Files/Amazon_pri_key.txt");
    byte[] keyBytes_Az_pri = Files.readAllBytes(path_Az_pri);
    
    System.out.println(" CLI-WS : ARRAY TO BYTES PUBLIC ARRAY: "+ Arrays.toString(keyBytes_Az_pub));
    
    System.out.println(" CLI-WS : ARRAY TO BYTES PRIVATE ARRAY: "+ Arrays.toString(keyBytes_Az_pri));
    
    PrivateKey privateKey_WebServer = EncDec.bytesToPrivKey(keyBytes_Az_pri);
    
    ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
	
	outputStream1.write(("1||Amazon||Mourya"+getDigest("mourya").getBytes()).getBytes());
	//outputStream1.write(base64.encode(sessionKey_Broker_byte).getBytes());
	outputStream1.write(("||").getBytes());
	//outputStream1.write(base64.encode(keyBytes_Az_pri).getBytes());
	outputStream1.write(("NONCE").getBytes());
	outputStream1.write(("||").getBytes());
	
	outputStream1.write(getDigest((("1||Amazon||Mourya"+getDigest("mourya").getBytes()))+("||")+("NONCE")).getBytes());
	
    
    byte[] Encoded_sessionKey_WebServer_byte = keygen.encryptWithPubKey(outputStream1.toByteArray(), publicKey_WebServer);
    
    byte[] Double_Encoded_sessionKey_WebServer_byte = keygen.encryptWithPriKey(Encoded_sessionKey_WebServer_byte, privateKey_WebServer);
    
    System.out.println("ENCODING BYTE SIZE OF PUB KEY ENCRYPTION: " + Double_Encoded_sessionKey_WebServer_byte.length);
    
    byte[] decoded_Authentication = keygen.decryptWithPrivKey(keygen.decryptWithPubKey(Double_Encoded_sessionKey_WebServer_byte, publicKey_WebServer), privateKey_WebServer);
    
    
    
    
}
}