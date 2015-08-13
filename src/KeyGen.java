import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Hashtable;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import sun.misc.BASE64Encoder;
 
@SuppressWarnings("restriction")
public class KeyGen{
	
	String[] keyList = new String[2];
	KeyPair pair = null;
	static Hashtable<String, PublicKey> Pub_Entity = new Hashtable<String, PublicKey>();
	
    protected KeyPair generate(String entity){
 
        try {
 
            // Create the public and private keys
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            BASE64Encoder base64 = new BASE64Encoder();
 
            generator.initialize(1024, new SecureRandom());
 
            pair = generator.generateKeyPair();
            PublicKey pubKey = pair.getPublic();
            PrivateKey privKey = pair.getPrivate();
            
            keyList[0] = base64.encode(pubKey.getEncoded()); 
            keyList[1] = base64.encode(privKey.getEncoded());
            
            Pub_Entity.put(entity, pubKey);
            
            System.out.println(entity + " PUBLIC KEY " + Pub_Entity.get(entity));
            System.out.println(entity + " PUBLIC KEY " + privKey);
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return pair;
		
    }

public PublicKey getPubKey(String entity)
{
	return Pub_Entity.get(entity);
}

protected SecretKey getSessionKey(){
    	
    	SecretKey SecKey = null;
    	 
        try {
 
        	KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
            KeyGen.init(128);

            SecKey = KeyGen.generateKey();
           
     
        }
        catch (Exception e) {
            System.out.println(e);
        }
        
        return SecKey;
		
    }
}