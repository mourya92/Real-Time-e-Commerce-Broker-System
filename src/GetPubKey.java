import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class GetPubKey {


	public PublicKey getPublicKey(String pubKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		FileInputStream fis = new FileInputStream(pubKeyFile);
        DataInputStream dis = new DataInputStream(fis);
        
        Path path = Paths.get(pubKeyFile);
        byte[] keyBytes = Files.readAllBytes(path);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey PubKey = keyFactory.generatePublic(keySpec);
 
        return PubKey; 
	}
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}

