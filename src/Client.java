import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


public class Client implements Runnable {

	static String pubKeyFile;
    static String priKeyFile; 
    static byte[] keyList;
    
    static ServerSocket serverSocket= null;
    static int portNumber_Broker = 17354; 
    static Socket clientSocket = null ;
    static int Broker_connected = 0; 
    static Socket socket_for_Broker = null; 
    static PublicKey my_pub_key = null;
	static PrivateKey my_private_key = null;
    static SecretKey sessionKey_Broker = null; 
    static SecretKey sessionkey_WebServer=null; 
    static PublicKey publicKey_Broker = null; 
    static PublicKey publicKey_WebServer = null;
    static String NONCE_CliAuth = null;
    static String prodCatRequest= null;
    static EncDec encodeDecode = new EncDec(); 
    
    static String product_ID = null;
    @SuppressWarnings("restriction")
	static BASE64Encoder encoder = new BASE64Encoder();
    
    static InputStream inFromBroker = null; 
    static DataInputStream stream_Broker = null; 
    static DesEncrypter DES_EncDec_Broker = null;  
    static DesEncrypter DES_EncDec_WebServer = null; 
    
    static byte[] iv_Broker = null;
    static byte[] iv_WebServer = null; 
    
    static String key_for_Encrypt_File = "Mary has one cat";
    static EncryptFile encFile = new EncryptFile();
    
    static BASE64Decoder decode_IncomingMessage = new BASE64Decoder();
    
    
/*    
    public Client() {
		// TODO Auto-generated constructor stub
		
		 pubKeyFile = "Client_pub_key.txt";
	     priKeyFile = "Client_pri_key.txt";
	     keyList = new KeyGenerator().generate();
	}
*/
	@SuppressWarnings("restriction")
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		 //*********************************************** PUBLIC PRIVATE KEY GEN START ************************************************//
		
		pubKeyFile = "../Files/Client_pub_key.txt";
	    priKeyFile = "../Files/Client_pri_key.txt";
	    
	    EncDec keygen = new EncDec();
		KeyPair pair = keygen.newKeyPair(1024);
	    
	    Path path = Paths.get("../Files/Broker_pub_key.txt");
        byte[] keyBytes = Files.readAllBytes(path);

        publicKey_Broker = encodeDecode.bytesToPubKey(keyBytes);
                
	//	System.out.println("RETRIEVED PUBLIC KEY OF BROKER :" + publicKey_Broker);
		
	     my_pub_key = pair.getPublic();
	     my_private_key = pair.getPrivate();
	    
	    System.out.println(" CLIENT PUBLIC KEY : CREATED");
	    FileOutputStream key_writer = new FileOutputStream(pubKeyFile);
	    key_writer.write(my_pub_key.getEncoded());
	    key_writer.close();
        
	    System.out.println(" CLIENT PRIVATE KEY : CREATED");
//	    key_writer = new FileOutputStream(priKeyFile);
//        key_writer.write(my_private_key.getEncoded());
//        key_writer.close();
        
	    serverSocket= new ServerSocket(portNumber_Broker);
	     
	   
        //*********************************************** PUBLIC PRIVATE KEY GEN END ************************************************//
        
        
        //*********************************************** AUTHENTICATION ************************************************//
        String serverName = ManagementFactory.getRuntimeMXBean().getName();
        
        System.out.println("MY NAME : " + serverName.split("@")[1]);
    
        System.out.println("CONNECTING TO... " + "net02.utdallas.edu" + " ON PORT " + portNumber_Broker);
		
        socket_for_Broker = new Socket("net02.utdallas.edu", portNumber_Broker);
		System.out.println("JUST CONNECTED TO "+ socket_for_Broker.getInetAddress().getHostName());
		
		System.out.println(" /*****************  CLIENT AUTHENTICATION ***************/ ");
		
		System.out.println(" ALGORITHM USED     : RSA" );
		System.out.println(" KEY LENGTH         : 1024 BITS");
		System.out.println(" CHAINING ALGORITHM : ECB");
		System.out.println(" PADDING            : NO PADDING");
		
		System.out.println("PLEASE ENTER WEB SERVER : ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String webServer = br.readLine();
		
		System.out.println("PLEASE ENTER USER NAME : ");
		br = new BufferedReader(new InputStreamReader(System.in));
		String userName = br.readLine();
		
		System.out.println("PLEASE ENTER PASSWORD : ");
		br = new BufferedReader(new InputStreamReader(System.in));
		String passWord = br.readLine();
		
		//********************************************    CLIENT AUTHENTICATION ******************************// 
		get_authenticated(webServer, userName, passWord);
		
		inFromBroker = socket_for_Broker.getInputStream();
		stream_Broker = new DataInputStream(inFromBroker);
		
		String msgFromBroker = stream_Broker.readUTF(); 
		
		byte[] cipherText_byte = decode_IncomingMessage.decodeBuffer(msgFromBroker.trim());

		byte[] decrypted_Auth_Pri_array = encodeDecode.decryptWithPrivKey(cipherText_byte, my_private_key);
		
		byte[] decrypted_Auth_Pub_array = encodeDecode.decryptWithPubKey(decrypted_Auth_Pri_array, publicKey_Broker);
		
		msgFromBroker = new String(decrypted_Auth_Pub_array);  
		
		System.out.println("BROKER's REPLY :" + msgFromBroker+":");
		
		if(msgFromBroker.split("\\|\\|")[0].contains("NOT")==true)
		{
			System.out.println(" AUTHENTICATION STAUS :  NOT AUTHENTICATED ");
			
			System.out.println(" I AM NOT AUTHENTICATED :( ");
			System.exit(1); 
		}
		
		//****************************************************************************************************//
		
		//***************************** SHARING SESSION KEY OF CLIENT-BROKER AND CHALLENGE MESSAGE *******************//
		
		if((msgFromBroker.split("\\|\\|")[0].contains("NOT")==false)&&(msgFromBroker.split("\\|\\|")[1].equalsIgnoreCase(NONCE_CliAuth)==true))
		{
			System.out.println(" AUTHENTICATION STAUS :  AUTHENTICATED ");
			
			System.out.println(" /*****************  *************** ***************/ ");
			
			System.out.println("\n\n\n /*****************  SESSION KEY EXCHANGE BETWEEN CLIENT- BROKER ***************/ ");
			
			System.out.println(" ALGORITHM USED     : AES" );
			System.out.println(" KEY LENGTH         : 128 BITS");
			System.out.println(" CHAINING ALGORITHM : CBC");
			System.out.println(" PADDING            : PKCS5 PADDING");
			
			SecureRandom random_Broker = new SecureRandom();
			  iv_Broker = new byte[16];
			  random_Broker.nextBytes(iv_Broker);
			  
			  
			sessionKey_Broker = new KeyGen().getSessionKey(); 
			DES_EncDec_Broker = new DesEncrypter(sessionKey_Broker,iv_Broker);
			
			System.out.println(" CLIENT CREATED SESSION KEY ");
			System.out.println(" CHALLENGE MESSAGE SENT BY CLIENT FOR BROKER : \"CHALLENGE\" ");
			//DES_EncDec_Broker = new DesEncrypter(sessionKey_Broker);
			byte[] share_SessionKey_Broker_Client = share_SessionKey_Broker_Client("CHALLENGE", msgFromBroker.split("\\|\\|")[2]); 
						
			send_Message(share_SessionKey_Broker_Client);
			
			String encoded_Challenge = stream_Broker.readUTF();			
			
			//System.out.println("RECEIVED BYTES LENGTH:"+encoded_Challenge.getBytes().length);
			//System.out.println("RECEIVED BYTES :"+ Arrays.toString(encoded_Challenge.getBytes()));
			
			
			String decoded_Challenge = DES_EncDec_Broker.decrypt(encoded_Challenge); 
		
		//	System.out.println("DECODED CHALLENGE MESSAGE IS :"+ decoded_Challenge);
			
			if(decoded_Challenge.equals("CHALLENGE")==true)
			{
				System.out.println(" CHALLENGE MESSGAE RECEIVED BY CLIENT : " +"\""+ decoded_Challenge + "\"");
				System.out.println(" BROKER AUTHENTICATED ");
				
				System.out.println(" /**********************  ********************************************* ***************/ ");
				
				System.out.println("\n\n\n /*****************  SESSION KEY EXCHANGE BETWEEN CLIENT- WEB SERVER ***************/ ");
				
				System.out.println(" ALGORITHM USED     : AES" );
				System.out.println(" KEY LENGTH         : 128 BITS");
				System.out.println(" CHAINING ALGORITHM : CBC");
				System.out.println(" PADDING            : PKCS5 PADDING");
				
				/*************************************************** SHARING SESSION KEY BETWEEN WEBSERVER-CLIENT ************************/
				SecureRandom random_WebServer = new SecureRandom();
				  iv_WebServer = new byte[16];
				  random_WebServer.nextBytes(iv_WebServer);
				  
				if(webServer.equalsIgnoreCase("Amazon")==true)
				{
					sessionkey_WebServer = new KeyGen().getSessionKey();
					DES_EncDec_WebServer = new DesEncrypter(sessionkey_WebServer, iv_WebServer);
					
					System.out.println(" CLIENT CREATED SESSION KEY FOR  : AMAZON");
					
					Path path_Az = Paths.get("../Files/Amazon_pub_key.txt");
			        byte[] keyBytes_Az = Files.readAllBytes(path_Az);

			        publicKey_WebServer = encodeDecode.bytesToPubKey(keyBytes_Az);
			        
				}
				if(webServer.equalsIgnoreCase("Ebay")==true)
				{
					sessionkey_WebServer = new KeyGen().getSessionKey();
					DES_EncDec_WebServer = new DesEncrypter(sessionkey_WebServer, iv_WebServer);
					
					System.out.println(" CLIENT CREATED SESSION KEY FOR  : EBAY");
					
					Path path_Eb = Paths.get("../Files/Ebay_pub_key.txt");
			        byte[] keyBytes_Eb = Files.readAllBytes(path_Eb);

			        publicKey_WebServer = encodeDecode.bytesToPubKey(keyBytes_Eb);
			        
				}
				
				String auth_WebServer = share_SessionKey_WebServer_Client("CHALLENGE"); 
				System.out.println(" CHALLENGE MESSAGE SENT BY CLIENT FOR WEB SERVER: \"CHALLENGE\" ");
				
				send_Message(auth_WebServer);
				
				
				String Client_WS_Challenge = stream_Broker.readUTF();				
				String decoded_WS_Challenge = DES_EncDec_WebServer.decrypt(Client_WS_Challenge);
				
				if(decoded_WS_Challenge.equalsIgnoreCase("CHALLENGE")== true)
				{
				//System.out.println("DECODED REPLY FROM WEB SERVER CHALLENGE MESSAGE :"+ decoded_WS_Challenge);
				
					System.out.println(" CHALLENGE MESSGAE RECEIVED BY CLIENT : " +"\""+ decoded_Challenge + "\"");
					System.out.println(" WEB-SERVER AUTHENTICATED ");
					
					System.out.println(" /**********************  ********************************************* ***************/ ");
					
					System.out.println("\n\n\n /*****************  PRODUCT CATALOGUE REQUEST BY CLIENT ***************/ ");
					
					/**************************************************************************************************************************/
				
				/*************************************************** PRODUCT CATALOGUE REQUEST ******************************************/
				
				System.out.println("PLEASE ENTER PRODUCT REQUEST : ");
				br = new BufferedReader(new InputStreamReader(System.in));
				String prodCatRequest = br.readLine();
				
				send_ProductCatalogue(prodCatRequest);	
				
				String encoded_Product_List = stream_Broker.readUTF();		
				
			//	System.out.println("ENCODED PART OF PROD LIST: "+encoded_Product_List);
				String decoded_Product_List = DES_EncDec_WebServer.decrypt(DES_EncDec_Broker.decrypt(encoded_Product_List));
				
				System.out.println(" /*****************  ******************************* ***************/ ");
				
				System.out.println("\n\n\n /*****************  PRODUCT CATALOGUE RECEIVED BY CLIENT ***************/ ");
				
				System.out.println("RECEIVED PRODUCT LIST: "+ decoded_Product_List);
				
				ArrayList<Integer> Prod_List_IDs = new ArrayList<Integer>(); 
		
				int i =0, attempts=0; 
				
				System.out.println("PRODUCT ID       NAME       		 PRICE");
				System.out.println("***********     *******    		    *******");
				
				for(String each : decoded_Product_List.split("\\|\\|"))
				{
					i=0;
					for(String inside : each.split(":"))
					{
						if(i==0)
							Prod_List_IDs.add(Integer.parseInt(inside.trim()));
						
						System.out.printf(inside+ "       ");
						i++; 
					}
					System.out.println();
				}
				
				System.out.println(" /***************** ******************************  ***************/ ");
				
				System.out.println("\n\n\n /*****************  PRODUCT SELECTION BY CLIENT ***************/ ");
				
				while (true) {
					System.out.println("PLEASE SELECT A PRODUCT ID :");
					br = new BufferedReader(new InputStreamReader(System.in));
					product_ID = br.readLine();
					attempts++;
					
					if (Prod_List_IDs.contains(Integer.parseInt(product_ID)) == false) {
						System.out.println(" PLEASE ENTER A VALID KEY ID: ");
						
						System.out.println("ATTEMPTS LEFT: "+attempts);
					}
					else
					{
						attempts=0;
						
						//String encoded_Product_Selection = DES_EncDec_Broker.encrypt(product_ID+"||SIGNATURE");
						
					//	String Prod_ID_Signature = "SIGNATURE";
						System.out.println(" PRODUCT SELECTION REQUEST BY CLIENT ENCRPTED USING : SESSION-KEY BETWEEN CLIENT/BROKER ");
						send_Message(DES_EncDec_Broker.encrypt("5||"+product_ID+"||"+ getDigest(product_ID)));
						
						break; 
					}
					
					if(attempts>4)
						{
							System.out.println(" MAXIMUM ATTEMPTS REACHED... EXITING....");
							System.exit(1);
						}
				}
				System.out.println(" /***************** **************************  ***************/ ");
				
				System.out.println("\n\n\n /*****************  PAYMENT GATEWAY CLIENT ***************/ ");
				
				System.out.println("PLEASE ENTER PAYMENT :");
				br = new BufferedReader(new InputStreamReader(System.in));
				String payment = br.readLine();
				
				java.util.Date date= new java.util.Date();
				
				String signature_message = product_ID +":"+ payment +":"+ new Timestamp(date.getTime());
				
				System.out.println(" CLIENT SIGNS : PRODUCT ID, PAYMENT, TIME STAMP ");  
				
				byte[] encoded_Signature = encodeDecode.signature_generator(signature_message.getBytes(), my_private_key);
				
				//send_Message(DES_EncDec_Broker.encrypt("6||"+payment+"||"+signature_message+"||"+encoder.encode(encoded_Signature)+"||"+getDigest(payment)));
				
				System.out.println(" CLIENT SEND PAYMENT || MESSAGE THAT IS SIGNED || SIGNATURE || DIGEST ENCRYPTED USING : SESSION KEY BETWEEN CLIENT/BROKER ");
				send_Message(DES_EncDec_Broker.encrypt("6||"+payment+"||"+signature_message+"||"+encoder.encode(encodeDecode.encryptWithPriKey(signature_message.getBytes(), my_private_key))+"||"+getDigest(payment)+"||"+encoder.encode(encoded_Signature)));
				
				System.out.println(" /***************** **************************  ***************/ ");
				
				System.out.println("\n\n\n /*****************  CLIENT WAITING FOR PRODUCT ***************/ ");
				
				System.out.println("CLIENT WAITING ON PRODUCT ........ ");
				
				String encoded_Product = stream_Broker.readUTF();
				
				String decoded_Prod_Broker = DES_EncDec_Broker.decrypt(encoded_Product);
				
				if(decoded_Prod_Broker.equalsIgnoreCase("TRY AGAIN")==false){
					String final_Product = DES_EncDec_WebServer.decrypt(decoded_Prod_Broker);
					System.out.println(" CLIENT WILL RECEIVE : " + final_Product.trim().split("\\|\\|")[0]);
					
					@SuppressWarnings("resource")
					FileOutputStream writeFile = new FileOutputStream("../Files/decrypted_file");
					
					File outputFile = null; 
					String Prod_Type = new String(); 
					if(prodCatRequest.equalsIgnoreCase("songs")==true)
						 outputFile = new File("../Products/"+final_Product.trim().split("\\|\\|")[0].trim());
					else if(prodCatRequest.equalsIgnoreCase("movies")==true)
						 outputFile = new File("../Products/"+final_Product.trim().split("\\|\\|")[0].trim());
					else if(prodCatRequest.equalsIgnoreCase("images")==true)
						 outputFile = new File("../Products/"+final_Product.trim().split("\\|\\|")[0].trim());
						
					 File decryptedFile = new File("../Files/decrypted_file");
					 
					while (DES_EncDec_Broker.decrypt(stream_Broker.readUTF().trim()).equalsIgnoreCase("END")!=true)
					{
						writeFile.write(decode_IncomingMessage.decodeBuffer(DES_EncDec_Broker.decrypt(stream_Broker.readUTF().trim())));
					}
					
					encFile.decrypt(sessionkey_WebServer, decryptedFile, outputFile);
					
					System.out.println(" DONE : PLEASE CHECK YOUR DIRECTORY ");//System.out.println("PRODUCT :" + DES_EncDec_Broker.decrypt(DES_EncDec_WebServer.decrypt(stream_Broker.readUTF())));
					
					System.out.println(" /***************** *********** END ***************  ***************/ ");
					System.exit(1);
				}
				else
				{
					System.out.println("\n\n\n /*****************  PAYMENT GATEWAY CLIENT ***************/ ");
					
					System.out.println("PLEASE ENTER EXACT PAYMENT AGAIN:");
					br = new BufferedReader(new InputStreamReader(System.in));
					payment = br.readLine();
					
					signature_message = product_ID +":"+ payment +":"+ new Timestamp(date.getTime());
					
					System.out.println(" CLIENT SIGNS : PRODUCT ID, PAYMENT, TIME STAMP ");  
					
				    encoded_Signature = encodeDecode.signature_generator(signature_message.getBytes(), my_private_key);
					
				    //send_Message(DES_EncDec_Broker.encrypt("6||"+payment+"||"+signature_message+"||"+encoder.encode(encoded_Signature)+"||"+getDigest(payment)));
					
					System.out.println(" CLIENT SEND PAYMENT || MESSAGE THAT IS SIGNED || SIGNATURE || DIGEST ENCRYPTED USING : SESSION KEY BETWEEN CLIENT/BROKER ");
					
					//send_Message(DES_EncDec_Broker.encrypt("6||"+payment+"||"+encoder.encode(encoded_Signature)+"||"+getDigest(payment)));
					send_Message(DES_EncDec_Broker.encrypt("6||"+payment+"||"+signature_message+"||"+encoder.encode(encodeDecode.encryptWithPriKey(signature_message.getBytes(), my_private_key))+"||"+getDigest(payment)));
					
					
					System.out.println(" /***************** **************************  ***************/ ");
					
					System.out.println("\n\n\n /*****************  CLIENT WAITING FOR PRODUCT ***************/ ");
					
					System.out.println("CLIENT WAITING ON PRODUCT ........ ");
					
					encoded_Product = stream_Broker.readUTF();
					
					decoded_Prod_Broker = DES_EncDec_Broker.decrypt(encoded_Product);
					
					if(decoded_Prod_Broker.equalsIgnoreCase("CANCEL")==false){
						String final_Product = DES_EncDec_WebServer.decrypt(decoded_Prod_Broker);
						System.out.println(" CLIENT WILL RECEIVE : " + final_Product.trim().split("\\|\\|")[0]);
						
						@SuppressWarnings("resource")
						FileOutputStream writeFile = new FileOutputStream("../Files/decrypted_file");
						
						File outputFile = null; 
						String Prod_Type = new String(); 
						if(prodCatRequest.equalsIgnoreCase("songs")==true)
							 outputFile = new File("../Products/"+final_Product.trim().split("\\|\\|")[0].trim());
						else if(prodCatRequest.equalsIgnoreCase("movies")==true)
							 outputFile = new File("../Products/"+final_Product.trim().split("\\|\\|")[0].trim());
						else if(prodCatRequest.equalsIgnoreCase("images")==true)
							 outputFile = new File("../Products/"+final_Product.trim().split("\\|\\|")[0].trim());
							
						 File decryptedFile = new File("../Files/decrypted_file");
						 
						while (DES_EncDec_Broker.decrypt(stream_Broker.readUTF().trim()).equalsIgnoreCase("END")!=true)
						{
							writeFile.write(decode_IncomingMessage.decodeBuffer(DES_EncDec_Broker.decrypt(stream_Broker.readUTF().trim())));
						}
						
						encFile.decrypt(sessionkey_WebServer, decryptedFile, outputFile);
						
						System.out.println(" DONE : PLEASE CHECK YOUR DIRECTORY ");
						
						System.out.println(" /***************** *********** END ***************  ***************/ ");
						System.exit(1);
					}
					else
					{
						System.out.println("\n\n\n /*****************  PAYMENT GATEWAY CLIENT ***************/ ");
						
						System.out.println(" CLIENT RECEIVED : " + "PAYMENT FAILED");
						System.exit(1);
						
						System.out.println(" /***************** *********** END ***************  ***************/ ");
					}
				}
							
			}
			}	
			/**************************************************************************************************************/
			
			else
			{
				System.out.println(" BROKER FAILED TO AUTHENTICATE");
				
				System.exit(1);
				System.out.println(" /***************** *********** END ***************  ***************/ ");
			}
					
			
		}
		//********************************************************************************************************************************//
		
		
		(new Thread(new Client())).start(); // START RECEIVE THREAD
	}
	
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

	private static void send_ProductCatalogue(String prodCatRequest) throws Exception {
		// TODO Auto-generated method stub
		
		String product_catalog_msg = "4||";
		
		String msg_webserver_client = prodCatRequest;
		
		String encoded_webserer_msg = DES_EncDec_WebServer.encrypt(msg_webserver_client);
		
		String msg_broker_productcatalog =DES_EncDec_Broker.encrypt(product_catalog_msg+encoded_webserer_msg);
		
		System.out.println(" PRODUCT REQUEST IS ENCRYPTED USING : SESSION-KEY BETWEEN CLIENT/WEB-SERVER AND CLIENT/BROKER ");
		
		send_Message(msg_broker_productcatalog);
	}

	@SuppressWarnings("restriction")
	private static String share_SessionKey_WebServer_Client(String string) throws Exception {
	// TODO Auto-generated method stub
		
		String challenge_Msg_WebServer = "3||"; // THIS MESSAGE IS FOR BROKER AUTHENTICATION
		
		byte[] sessionKey_WebServer_byte = sessionkey_WebServer.getEncoded();
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		outputStream.write(encoder.encode(sessionKey_WebServer_byte).getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(encoder.encode(iv_WebServer).getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(encodeDecode.nonce_generator().getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(string.getBytes());
		
		System.out.println(" SESSION KEY ENCYPTED USING : PUBLIC KEY OF WEB-SERVER");
		byte[] Encoded_sessionKey_WebServer_byte = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publicKey_WebServer);
		
		String auth_WebServer = DES_EncDec_Broker.encrypt(challenge_Msg_WebServer + encoder.encode(Encoded_sessionKey_WebServer_byte));		
		
		System.out.println(" CLIENT SENDS ENCRYPTED SESSION KEY AGAIN ENCRYPTED UISNG : SESSION KEY BETWEEN CLIENT-BROKER");
		return auth_WebServer;
}

	@SuppressWarnings("restriction")
	private static byte[] share_SessionKey_Broker_Client(String challenge_Msg, String NONCE_by_Broker) throws Exception {
		// TODO Auto-generated method stub
		
		byte[] sessionKey_Broker_byte = sessionKey_Broker.getEncoded();
		
		
		System.out.println("SESSION KEY IN BYTE ARRAY:"+ Arrays.toString(sessionKey_Broker_byte)  );
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
		outputStream.write(("2||"+challenge_Msg+"||").getBytes());
		outputStream.write(encoder.encode(sessionKey_Broker_byte).getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(encoder.encode(iv_Broker).getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(NONCE_by_Broker.getBytes());
		
		byte[] challenge_Broker = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publicKey_Broker);
		
		System.out.println(" KEY EXCHANGE MESSAGE IS ENCRYPTED USING : PUBLIC KEY OF BROKER ");
		//System.out.println("BYTE ARRAY OF 2||CHALLANGE||AES KEY :"+ Arrays.toString(outputStream.toByteArray()));
		return challenge_Broker;
	}

	private static void get_authenticated(String webServer, String userName, String passWord) throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
	// TODO Auto-generated method stub
		
		MessageDigest md ; 
		md = MessageDigest.getInstance("MD5"); 
        md.update(passWord.getBytes());
           
        byte byteData[] = md.digest();
        
       StringBuffer hexString = new StringBuffer();
    	for (int i=0;i<byteData.length;i++) {
    		String hex=Integer.toHexString(0xff & byteData[i]);
   	     	if(hex.length()==1) hexString.append('0');
   	     	hexString.append(hex);
    	}
    	
    	/****************************/
    	
    	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
    	NONCE_CliAuth = encodeDecode.nonce_generator();
    	//String NONCE_CliAuth = "NONCE";
		outputStream.write(("1||"+webServer+"||"+userName+"||"+hexString.toString()).getBytes());
		//outputStream.write(encoder.encode(sessionKey_Broker_byte).getBytes());
		outputStream.write(("||").getBytes());
		//outputStream.write(encoder.encode(iv_Broker).getBytes());
		outputStream.write(NONCE_CliAuth.getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(getDigest(webServer+"||"+userName+"||"+hexString.toString()+"||"+NONCE_CliAuth).getBytes());
		
		//System.out.println("ENCODING BYTE SIZE : " + outputStream.toByteArray().length);
		
		byte[] pubKey_encoding_Auth = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publicKey_Broker); 
		
		//System.out.println("ENCODING BYTE SIZE OF PUB KEY ENCRYPTION: " + pubKey_encoding_Auth.length);
		
		byte[] authenticate_Client = encodeDecode.encryptWithPriKey(pubKey_encoding_Auth , my_private_key);
    	
    	System.out.println(" USERNAME/PASSWORD VERIFICATION IS ENCODED USING : PUBLIC KEY OF BROKER AND PRIVATE KEY OF CLIENT ");
		send_Message(authenticate_Client);
		
		/****************************/
    	
    	
    	//String message = webServer+"||"+userName+"||"+hexString.toString(); 
    	//send_Message(1, message); 
}

	//************************************************* SEND MESSAGE *********************************//
	@SuppressWarnings("unused")
	private static void send_Message(int msg_Type, String msg) throws IOException {
		// TODO Auto-generated method stub
		
		OutputStream outToBroker = socket_for_Broker.getOutputStream();
        DataOutputStream out = new DataOutputStream(outToBroker);
        
        msg = Integer.toString(msg_Type)+"||"+msg; 
        out.writeUTF(msg);
        
        //System.out.println("CLIENT SENT MESSAGE :"+msg);
		
	}
	
	private static void send_Message(String msg) throws IOException {
		// TODO Auto-generated method stub
		
		OutputStream outToBroker = socket_for_Broker.getOutputStream();
        DataOutputStream out = new DataOutputStream(outToBroker);
         
        out.writeUTF(msg);
        
      //  System.out.println("CLIENT SENT MESSAGE :"+msg);
		
	}
	
	private static void send_Message(byte[] msg) throws IOException{
		
		OutputStream outToBroker = socket_for_Broker.getOutputStream();
        DataOutputStream out = new DataOutputStream(outToBroker);
        
        @SuppressWarnings("restriction")
		String msg_send = encoder.encode(msg);
        
        out.writeUTF(msg_send);
	}
	
	//***********************************************************************************************//
	
	public void run() {
		// TODO Auto-generated method stub
		
		while(true)
		{
			System.out.println("CLIENT LISTENING...");
			
			try {
				clientSocket = serverSocket.accept();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			System.out.println("CLIENT ACCEPTED : " + clientSocket.getInetAddress());
		}
		
	}
}
