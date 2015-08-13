import java.beans.XMLEncoder;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 */

/**
 * @author mgudladona
 *
 */
public class Broker implements Runnable {

	/**
	 * Broker initially creates public key and private key and stores its public
	 * key in broker_pub_key.txt Also, it creates random number of users/clients
	 * and passwords for each of them and stores hash of them in a secure file.
	 * 
	 * Broker listens in port 3333 for incoming messages from Clients. Broker
	 * listens in port 3334 for incoming messages from Broker.
	 * 
	 */

	static String pubKeyFile;
	static String priKeyFile;
	static String User_PassFile;
	static String[] keyList;
	static KeyPair[] keyListPair = null;
	static PublicKey my_pub_key = null;
	static PrivateKey my_private_key = null;
	static PublicKey my_pub_key_signature = null;
	static PrivateKey my_private_key_signature = null;
	static PublicKey publiKey_Amazon = null;
	static PublicKey publiKey_Ebay = null;
	static PublicKey publicKey_Client = null;
	static PublicKey publiKey_WebServer = null;
	static SecretKey sessionKey_Cli_Bro = null;
	static SecretKey sessionKey_Bro_Amazon = null;
	static SecretKey sessionKey_Bro_Ebay = null;
	static SecretKey sessionKey_Bro_WebServer = null;

	static String userNames_Amazon[] = null;
	static String passWords_Amazon[] = null;
	static Hashtable<String, String> User_Pass_Amazon = null;
	
	static Hashtable<String, String> User_Auth_Nonce_Az = new Hashtable<String, String>();
	static Hashtable<String, String> User_Auth_Nonce_Eb = new Hashtable<String, String>();
	
	static String userNames_Ebay[] = null;
	static String passWords_Ebay[] = null;
	static Hashtable<String, String> User_Pass_Ebay = null;

	static Hashtable<String, String> type_1 = null;
	static String[] type_1_Structure = null;

	static int recvd_msgType = 0;
	static String recvd_webServer = null;
	static String recvd_UserName = null;
	static String recvd_passWord = null;
	String recvd_Auth_NONCE = null;
	String recvd_Auth_Digest = null;

	static ServerSocket serverSocket = null;
	static int portNumber_Client = 1546;
	static int portNumber_Broker = 17354;
	static int portNumber_Amazon = 18353;
	static int portNumber_Ebay = 9291;
	static Socket clientSocket = null;
	static Socket AmazonSocket = null;
	static Socket EbaySocket = null;
	static DataInputStream inputstream_Webserver = null;
	static DataOutputStream outputstream_Webserver = null;
	static List<String> nonce_array = new ArrayList<String>();
	static DesEncrypter DES_EncDec_Client = null;
	static DesEncrypter DES_EncDec_WebServer = null;

	DataInputStream inputstream_Client = null;
	DataInputStream inputstream_Amazon = null;
	DataInputStream inputstream_Ebay = null;
	static DataOutputStream outputstream_Client = null;
	DataOutputStream outputstream_Amazon = null;
	DataOutputStream outputstream_Ebay = null;

	static byte[] iv_WebServer = null;

	@SuppressWarnings("restriction")
	static BASE64Decoder decode_IncomingMessage = new BASE64Decoder();
	@SuppressWarnings("restriction")
	static BASE64Encoder encoder = new BASE64Encoder();

	static EncDec encodeDecode = new EncDec();
	
	static FileInputStream signature_File_read = null;
	static FileOutputStream signature_File_write = null;

	/**
	 * @param args
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		// TODO Auto-generated method stub

		// *********************************************** PUBLIC PRIVATE KEY
		// GEN START ************************************************//
		pubKeyFile = "../Files/Broker_pub_key.txt";
		priKeyFile = "../Files/Broker_pri_key.txt";
		User_PassFile = "User_Pass.txt";

		System.out.println(" BROKER PUBLIC KEY : CREATED");
		EncDec keygen = new EncDec();
		KeyPair pair = keygen.newKeyPair(1024);
		my_pub_key = pair.getPublic();
		my_private_key = pair.getPrivate();
		
		KeyPair pair_Signature = keygen.newKeyPair(1024);
		my_pub_key_signature = pair_Signature.getPublic();
		my_private_key_signature = pair_Signature.getPrivate();
		
		System.out.println(" BROKER PRIVATE KEY : CREATED");
		FileOutputStream key_writer = new FileOutputStream(pubKeyFile);
		key_writer.write(my_pub_key.getEncoded());
		key_writer.close();

		System.out.println(" /*****************  PUBLIC KEY PAIR GENERATION ***************/ ");
		
		System.out.println(" ALGORITHM USED     : RSA" );
		System.out.println(" KEY LENGTH         : 1024 BITS");
		System.out.println(" CHAINING ALGORITHM : ECB");
		System.out.println(" PADDING            : NO PADDING");
		
		System.out.println(" /*****************  *************** ***************/ ");
		
//		key_writer = new FileOutputStream(priKeyFile);
//		key_writer.write(my_private_key.getEncoded());
//		key_writer.close();

		Path path_Az = Paths.get("../Files/Amazon_pub_key.txt");
		byte[] keyBytes_Az = Files.readAllBytes(path_Az);

		publiKey_Amazon = encodeDecode.bytesToPubKey(keyBytes_Az);

		Path path_Eb = Paths.get("../Files/Ebay_pub_key.txt");
		byte[] keyBytes_Eb = Files.readAllBytes(path_Eb);

		publiKey_Ebay = encodeDecode.bytesToPubKey(keyBytes_Eb);

		// *********************************************** PUBLIC PRIVATE KEY
		// GEN END ************************************************//

		serverSocket = new ServerSocket(portNumber_Broker);

		userNames_Amazon = new String[] { "Mourya", "kk", "Karthik", "RaviP" };
		passWords_Amazon = new String[] { "mourya", "kk", "karthik", "ravip" };

		userNames_Ebay = new String[] { "Mourya", "kk", "Karthik", "RaviP" };
		passWords_Ebay = new String[] { "mourya", "kk", "karthik", "ravip" };

		type_1 = new Hashtable<String, String>();

		FileOutputStream fos = new FileOutputStream(User_PassFile);
		XMLEncoder e = new XMLEncoder(fos);

		User_Pass_Amazon = new Hashtable<String, String>();
		User_Pass_Ebay = new Hashtable<String, String>();

		createUserPassFile(User_Pass_Amazon, userNames_Amazon, passWords_Amazon);
		createUserPassFile(User_Pass_Ebay, userNames_Ebay, passWords_Ebay);
		
		init_CliAuthtable(User_Auth_Nonce_Az, userNames_Amazon);
		init_CliAuthtable(User_Auth_Nonce_Eb, userNames_Ebay);

		(new Thread(new Broker())).start(); // START RECEIVE THREAD

		String serverName = ManagementFactory.getRuntimeMXBean().getName();
		System.out.println("MY NAME : " + serverName.split("@")[1]);

		System.out.println("CONNECTING TO... " + "net03.utdallas.edu" + " ON PORT " + portNumber_Amazon);

		AmazonSocket = new Socket("net03.utdallas.edu", portNumber_Amazon);
		System.out.println("JUST CONNECTED TO " + AmazonSocket.getInetAddress().getHostName());

		System.out.println("CONNECTING TO... " + "net04.utdallas.edu" + " ON PORT " + portNumber_Ebay);

		EbaySocket = new Socket("net04.utdallas.edu", portNumber_Ebay);
		System.out.println("JUST CONNECTED TO " + EbaySocket.getInetAddress().getHostName());
	}

	private static void init_CliAuthtable(Hashtable<String, String> user_Nonce, String[] userNames_WS) {
		// TODO Auto-generated method stub
		
		for (String users : userNames_WS)
		{
			user_Nonce.put(users, "0");
		}
		
	}

	static void setMsgType(int type) {
		recvd_msgType = type;
	}

	static int getMsgType() {
		return recvd_msgType;
	}

	private static void createUserPassFile(Hashtable<String, String> User_Pass, String[] userNames, String[] passWords)
			throws FileNotFoundException {
		// TODO Auto-generated method stub

		MessageDigest md;

		int index = 0;

		try {

			for (String pass : passWords) {

				md = MessageDigest.getInstance("MD5");
				md.update(pass.getBytes());

				byte byteData[] = md.digest();

				StringBuffer hexString = new StringBuffer();
				for (int i = 0; i < byteData.length; i++) {
					String hex = Integer.toHexString(0xff & byteData[i]);
					if (hex.length() == 1)
						hexString.append('0');
					hexString.append(hex);
				}

				User_Pass.put(userNames[index], hexString.toString());

				// System.out.println("USER NAME : "+userNames[index] +
				// " PASSWORD : "+pass );
				index++;
			}
			System.out.println(" ****** USER-PASS FILE ******** ");
			System.out.println(User_Pass);
			System.out.println(" ************** ");

			FileOutputStream fos = new FileOutputStream(User_PassFile);
			XMLEncoder e = new XMLEncoder(fos);
			e.writeObject(User_Pass);
			e.close();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private boolean Authenticate(Hashtable<String, String> type, String msg_Body) throws FileNotFoundException {
		// TODO Auto-generated method stub

		String[] body = msg_Body.split("\\|\\|");

		recvd_webServer = body[0];
		recvd_UserName = body[1];
		recvd_passWord = body[2];
		recvd_Auth_NONCE = body[3];
		recvd_Auth_Digest = body[4];

		if (recvd_Auth_Digest.equalsIgnoreCase(getDigest(recvd_webServer + "||" + recvd_UserName + "||" + recvd_passWord
				+ "||" + recvd_Auth_NONCE)) == true) {

			type.put(recvd_UserName, recvd_passWord);
			System.out.println(" DIGEST IS EQUAL ");
			
			System.out.println(" RECEIVED STRUCTURE:" );
			System.out.println(type);
			
			

			
				if (recvd_webServer.equalsIgnoreCase("Amazon") == true) {
				if(recvd_Auth_NONCE.equalsIgnoreCase(User_Auth_Nonce_Az.get(recvd_UserName))==false)
				{
						System.out.println(User_Pass_Amazon.get(recvd_UserName));
						System.out.println(type.get(recvd_UserName));
						if ((type.get(recvd_UserName).equals(User_Pass_Amazon.get(recvd_UserName))) == true)
						{
							System.out.println(" AMAZON :  PASSWORD MATCHED ");
							signature_File_read = new FileInputStream("../Files/Signature_File_Amazon_"+recvd_UserName);
							signature_File_write = new FileOutputStream("../Files/Signature_File_Amazon_"+recvd_UserName);
							
							User_Auth_Nonce_Az.put(recvd_UserName, recvd_Auth_NONCE);
							 return true;
						}
				}
					
					}

					else if (recvd_webServer.equalsIgnoreCase("Ebay") == true) {
						if(recvd_Auth_NONCE.equalsIgnoreCase(User_Auth_Nonce_Eb.get(recvd_UserName))==false){
						if ((type.get(recvd_UserName).equals(User_Pass_Ebay.get(recvd_UserName))) == true)
						{
							System.out.println(" EBAY : PASSWORD MATCHED ");
							signature_File_read = new FileInputStream("../Files/Signature_File_Ebay_"+recvd_UserName);
							signature_File_write = new FileOutputStream("../Files/Signature_File_Ebay_"+recvd_UserName);
							
							User_Auth_Nonce_Eb.put(recvd_UserName, recvd_Auth_NONCE);
							return true;
						}
						}
					}
		
			}
		return false;


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

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return hexString.toString();
	}

	@SuppressWarnings("unused")
	private static void send_Message(byte[] msg) throws IOException{
		
        
        @SuppressWarnings("restriction")
		String msg_send = encoder.encode(msg);
        
        outputstream_Client.writeUTF(msg_send);
	}

@SuppressWarnings("restriction")
	public void run() {
		// TODO Auto-generated method stub

		while (true) {
			System.out.println("BROKER LISTENING FOR CLIENT...");

			try {
				clientSocket = serverSocket.accept();

				System.out.println("BROKER ACCEPTED CLIENT : " + clientSocket.getInetAddress().getHostName());

				String client_name = clientSocket.getInetAddress().getHostName();
				Integer port_number = clientSocket.getPort();
				
				String client_id = client_name + String.valueOf(port_number);
				
				InputStream inFromServer = clientSocket.getInputStream();
				inputstream_Client = new DataInputStream(inFromServer);

				InputStream inFromAz = AmazonSocket.getInputStream();
				inputstream_Amazon = new DataInputStream(inFromAz);

				InputStream inFromEb = EbaySocket.getInputStream();
				inputstream_Ebay = new DataInputStream(inFromEb);

				OutputStream outToClient = clientSocket.getOutputStream();
				outputstream_Client = new DataOutputStream(outToClient);

				OutputStream outToAz = AmazonSocket.getOutputStream();
				outputstream_Amazon = new DataOutputStream(outToAz);

				OutputStream outToEb = EbaySocket.getOutputStream();
				outputstream_Ebay = new DataOutputStream(outToEb);

				// String msgFromClient =
				// inputstream_Client.readUTF().split("/")[0];

				String msgFromClient = inputstream_Client.readUTF();

				Path path_Client = Paths.get("../Files/Client_pub_key.txt");
				byte[] keyBytes_Client = Files.readAllBytes(path_Client);

			//	System.out.println("READ BYTES OF PUBLIC KEY OF CLIENT IS: " + keyBytes_Client.length);

				publicKey_Client = encodeDecode.bytesToPubKey(keyBytes_Client);

				byte[] encoded_Authentication = decode_IncomingMessage.decodeBuffer(msgFromClient);

			//	System.out.println("DECODED BYTE SIZE OF PUB KEY ENCRYPTION: " + encoded_Authentication.length);

				byte[] decoded_PubKey_Auth = encodeDecode.decryptWithPubKey(encoded_Authentication, publicKey_Client);

				byte[] decoded_Authentication = encodeDecode.decryptWithPrivKey(decoded_PubKey_Auth, my_private_key);

				String client_Authentication = new String(decoded_Authentication);

			//	System.out.println(" RECEIVED MESSAGE TOKENS ARE : ");

				String[] recvd_MsgTokens = client_Authentication.split("\\|\\|");

				setMsgType(Integer.parseInt(client_Authentication.trim().split("\\|\\|")[0]));

				switch (getMsgType()) {
				case 1:
					
					System.out.println(" /************************** USER AUTHENTICATION *************************/ \n\n");

					if (true == Authenticate(type_1, client_Authentication.split("\\|\\|", 2)[1])) {

						System.out.println(" SUCCESSFULLY LOGGED IN !!!! ");
						
						String NONCE_BRO_CLI = encodeDecode.nonce_generator();
						
						System.out.println(" /************************** ************* *************************/ \n\n");
						
						
						System.out.println(" /************************** BROKER SHARING NONCE TO CLIENT *************************/ \n\n");
						
						System.out.println(" NONCE TO BE SHARED : "+NONCE_BRO_CLI);
						
						
						byte[] priKey_encoding_Auth = encodeDecode.encryptWithPriKey( ("AUTHENTICATED"+"||"+ recvd_Auth_NONCE +"||"+NONCE_BRO_CLI).getBytes(), my_private_key);
						
						
						byte[] send_Ack_Client = encodeDecode.encryptWithPubKey(priKey_encoding_Auth, publicKey_Client); 
						
						System.out.println(" THIS MESSSAGE IS ENCRYPTED USING PRIVATE KEY OF BROKER AND PUBLICK KEY OF CLIENT ");
						
						//System.out.println("ENCODING BYTE SIZE OF PUB KEY ENCRYPTION: " + pubKey_encoding_Auth.length);
						
						
						
						//outputstream_Client.writeUTF("AUTHENTICATED"+"||"+ recvd_Auth_NONCE +"||"+NONCE_BRO_CLI);
						
						send_Message(send_Ack_Client);

						/**************** CHALLENGE MESSAGE FROM CLIENT TO BROKER **************/

						String Challenge = new String();
						String Challenge_Msg = new String();

						Challenge_Msg = inputstream_Client.readUTF();

						System.out.println(" /************************** BROKER FACING CHALLENGE MESSAGE *************************/ \n\n");
						
						byte[] cipherText_byte = decode_IncomingMessage.decodeBuffer(Challenge_Msg);

						byte[] decrypted_array = encodeDecode.decryptWithPrivKey(cipherText_byte, my_private_key);

						setMsgType(Integer.parseInt(new String(decrypted_array).trim().split("\\|\\|")[0]));

					//	System.out.println(" RECEIVED MESSAGE TYPE :" + getMsgType());

						Challenge = new String(decrypted_array).trim().split("\\|\\|")[1];

					//	System.out.println(" STRING IN FORM OF BYTE ARRAY:" + Arrays.toString(decrypted_array));

						System.out.println("RECEIVED CHALLENGE MESSAGE FROM CLIENT :" + Challenge);

						System.out.println("PROBABLE SESSION KEY BYTES:"
								+ Arrays.toString(decode_IncomingMessage.decodeBuffer(new String(decrypted_array)
										.trim().split("\\|\\|")[2])));

						byte[] sessionKey_byte = Arrays.copyOfRange(decrypted_array, 14, 30);

						System.out.println("SESSION KEY BYTE:" + Arrays.toString(sessionKey_byte));

						sessionKey_Cli_Bro = new SecretKeySpec(decode_IncomingMessage.decodeBuffer(new String(
								decrypted_array).trim().split("\\|\\|")[2]), 0,
								decode_IncomingMessage
										.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[2]).length,
								"AES");

						DES_EncDec_Client = new DesEncrypter(sessionKey_Cli_Bro,
								decode_IncomingMessage
										.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[3]));
						
						System.out.println(" SESSION KEY RETREIVED FROM CLIENT ");
						System.out.println(" ALGORITHM USED : AES");

						String encrypted_Challenge = DES_EncDec_Client.encrypt(Challenge);

						String nonce = new String(decrypted_array).trim().split("\\|\\|")[4];
						
						System.out.println(" NONCE RECEIVED FROM CLIENT IS : "+nonce);
						
						//if(!nonce_array.contains(client_id+nonce) || nonce_array == null)
						if((nonce.equalsIgnoreCase(NONCE_BRO_CLI)==true)&&(!nonce_array.contains(client_id+nonce) || nonce_array == null))
						{	
							nonce_array.add(client_id+nonce);
						}
						
						
						else
						{
							System.out.println("Replay Attack Detected!!!!!!....aborting programm!!!");
							System.exit(0);
						}
						
						outputstream_Client.writeUTF(encrypted_Challenge);
						outputstream_Client.flush();
						
						System.out.println(" /************************** ********************  *************************/ \n\n");
					//	System.out.println("BYTES WRITTEN TILL NOW FROM BROKER :" + outputstream_Client.size());
					//	System.out.println("SENT BYTES LENGTH:" + encrypted_Challenge.getBytes().length);
					//	System.out.println("SENT BYTES :" + Arrays.toString(encrypted_Challenge.getBytes()));

						/******************************************************************/

						/**************** CHALLENGE MESSAGE FROM CLIENT TO WEB SERVER **************/

						System.out.println("\n\n\n /*****************  SESSION KEY FORWARD BETWEEN CLIENT- WEB SERVER ***************/ ");
						
						String auth_WS = inputstream_Client.readUTF();

						String auth_WS_decoded = DES_EncDec_Client.decrypt(auth_WS);

						setMsgType(Integer.parseInt(new String(auth_WS_decoded).trim().split("\\|\\|")[0]));

						System.out.println("BRO-WS RECEIVED MESSAGE TYPE :" + getMsgType());

						if (recvd_webServer.equals("Amazon") == true) {

							inputstream_Webserver = inputstream_Amazon;
							outputstream_Webserver = outputstream_Amazon;
							publiKey_WebServer = publiKey_Amazon;

						}

						if (recvd_webServer.equals("Ebay") == true) {

							inputstream_Webserver = inputstream_Ebay;
							outputstream_Webserver = outputstream_Ebay;
							publiKey_WebServer = publiKey_Ebay;
						}

						byte[] tmp = decode_IncomingMessage.decodeBuffer(auth_WS_decoded.trim().split("\\|\\|")[1]);

						outputstream_Webserver.writeUTF(auth_WS_decoded.trim().split("\\|\\|")[1]);

						String reply_WebServer_Auth = inputstream_Webserver.readUTF();
						outputstream_Client.writeUTF(reply_WebServer_Auth);
						
						System.out.println(" /***************** ****************************** ***************/ ");

						/**************************************************************************/

						/**************** CHALLENGE MESSAGE FROM BROKER TO WEB SERVER **************/

						String product_catalog_msg = inputstream_Client.readUTF();

						KeyGenerator Keygen = KeyGenerator.getInstance("AES");
						Keygen.init(128);

						sessionKey_Bro_WebServer = Keygen.generateKey();

						System.out.println("\n\n\n /*****************  SESSION KEY EXCHANGE BETWEEN CLIENT- WEB SERVER ***************/ ");
						
						System.out.println(" ALGORITHM USED     : AES" );
						System.out.println(" KEY LENGTH         : 128 BITS");
						System.out.println(" CHAINING ALGORITHM : CBC");
						System.out.println(" PADDING            : PKCS5 PADDING");
						
						byte[] sessionKey_BrokerAmazon_byte = sessionKey_Bro_WebServer.getEncoded();
						String challenge_Msg = "CHALLENGE";

						System.out.println(" CHALLENGE MESSAGE SENT BY BROKER FOR WEB SERVER: \"CHALLENGE\" ");
						
						SecureRandom random_WebServer = new SecureRandom();
						iv_WebServer = new byte[16];
						random_WebServer.nextBytes(iv_WebServer);

						ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

						System.out.println(" MESSAGE SENT BY BROKER CHALLENGE || ENCRYPTED SESSION KEY || IV || NONCE IS ENCRYPTED USING : PUBLIC KEY OF WEB-SERVER/ PRIVATE KEY OF BROKER");
						
						outputStream.write(("2||"+challenge_Msg+"||").getBytes());
						outputStream.write(encoder.encode(sessionKey_BrokerAmazon_byte).getBytes());
						outputStream.write(("||").getBytes());
						outputStream.write(encoder.encode(iv_WebServer).getBytes());
						outputStream.write(("||").getBytes());
						outputStream.write(encodeDecode.nonce_generator().getBytes());

						DES_EncDec_WebServer = new DesEncrypter(sessionKey_Bro_WebServer, iv_WebServer);

						//byte[] challenge_Amazon = encodeDecode.encryptWithPriKey(encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publiKey_WebServer), my_private_key);

						byte[] pubKey_encoding_Auth = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publiKey_WebServer); 
						
						//System.out.println("ENCODING BYTE SIZE OF PUB KEY ENCRYPTION: " + pubKey_encoding_Auth.length);
						
						byte[] challenge_Amazon = encodeDecode.encryptWithPriKey(pubKey_encoding_Auth , my_private_key);
						
						String msg_send = encoder.encode(challenge_Amazon);
						
						outputstream_Webserver.writeUTF(msg_send);
						
						

						String encoded_Challenge = inputstream_Webserver.readUTF();

						String decoded_Challenge = (DES_EncDec_WebServer.decrypt(encoded_Challenge));

						System.out.println(" CHALLENGE MESSAGE FROM WEB-SERVER IS :" + decoded_Challenge);

						if (decoded_Challenge.equals(challenge_Msg) == true) {
							System.out.println("WEB-SERVER AUTHENTICATED !! ");
						}
						
						System.out.println("/*****************  ********************************************** ***************/ ");
						
						/**************************************************************************/

						/**************** PRODUCT CATALOGUE REQUEST FORWARDED BY BROKER **************/
						
						System.out.println("\n\n\n /*****************  PRODUCT CATALOGUE REQUEST FORWARDED BY BROKER  ***************/ ");

						String decrypted_product_catalog = DES_EncDec_Client.decrypt(product_catalog_msg);

						System.out.println("PRODUCT CATALOGUE MESSAGE RECEIVED IS :" + decrypted_product_catalog);

						setMsgType(Integer.parseInt(new String(decrypted_product_catalog).trim().split("\\|\\|")[0]));

						outputstream_Webserver.writeUTF(DES_EncDec_WebServer.encrypt(decrypted_product_catalog.trim()
								.split("\\|\\|")[1]));

						/**************************************************************************/
						
						System.out.println("/*****************  ********************************************** ***************/ ");

						
						/**************** PRODUCT CATALOGUE SENT BY WEB SERVER **************/
						
						System.out.println("\n\n\n /*****************  PRODUCT CATALOGUE SENT BY WEB SERVER  ***************/ ");

						String encoded_Prod_List = inputstream_Webserver.readUTF();

						String decoded_Prod_List = DES_EncDec_WebServer.decrypt(encoded_Prod_List);
						
						System.out.println("          CANNOT READ. JUST FORWARDED         ");

						outputstream_Client.writeUTF(DES_EncDec_Client.encrypt(decoded_Prod_List));

						/********************************************************************/

						/**************** PRODUCT REQUEST RECEIVED BY BROKER FROM CLIENT **************/
						
						System.out.println("\n\n\n /*****************  PRODUCT CATALOGUE SENT BY WEB SERVER  ***************/ ");

						String encoded_Prod_Digest_selection = inputstream_Client.readUTF();

						String decoded_Prod_Digest_Selection = DES_EncDec_Client.decrypt(encoded_Prod_Digest_selection);

						String digest_ProdID = decoded_Prod_Digest_Selection.split("\\|\\|")[2];

						String Prod_ID_toForward = decoded_Prod_Digest_Selection.split("\\|\\|")[1];

						if (digest_ProdID.equals(getDigest(Prod_ID_toForward)))
							System.out.println(" DIGEST IS EQUAL ");
						else
							System.out.println(" DIGEST DID NOT MATCH ");
						
						System.out.println(" RECEIVED PRODUCT ID:" + Prod_ID_toForward);					

						outputstream_Webserver.writeUTF(DES_EncDec_WebServer.encrypt(Prod_ID_toForward));
						
						System.out.println("/*****************  ********************************************** ***************/ ");

						/********************************************************************/

						/********************************** PAYMENT GATEWAY **************************************/
						
						System.out.println("\n\n\n /*****************  PAYMENT GATEWAY  ***************/ ");

						String encoded_Payment = inputstream_Client.readUTF(); 
						
						String decoded_Payment_Signature = 	 DES_EncDec_Client.decrypt(encoded_Payment); 
						String received_Payment = decoded_Payment_Signature.split("\\|\\|")[1]; 
						
						String sign_timestamp = decoded_Payment_Signature.split("\\|\\|")[2];

						byte[] decoded_Array_Signature = decode_IncomingMessage.decodeBuffer(decoded_Payment_Signature.split("\\|\\|")[3]);

						byte[] decoded_Array_Signature1 = decode_IncomingMessage.decodeBuffer(decoded_Payment_Signature.split("\\|\\|")[5]);
						
						System.out.println("the signature of the message is :"+ encodeDecode.verify_signature(sign_timestamp.getBytes(), decoded_Array_Signature1, publicKey_Client) );
						
						byte[] decoded_withPriKey_Array = encodeDecode.decryptWithPubKey(decoded_Array_Signature,publicKey_Client);
						
						byte[] signature_Encoded_Broker_priKey = encodeDecode.encryptWithPriKey(decoded_Array_Signature, my_private_key_signature);
						
						System.out.println(" PAYMENT IS STORED BY ENCRYPTING WITH CLIENT PRIVTE KEY AND A SECOND PRIVATE KEY FROM BROKER ");
						
						signature_File_write.write(signature_Encoded_Broker_priKey);
						
						byte[] verifying_Signature = new byte[signature_Encoded_Broker_priKey.length];
						
						signature_File_read.read(verifying_Signature);
						
						System.out.println(" SIGNATURE WRITTEN TO A FILE ");
						System.out.println(new String(decoded_withPriKey_Array));
						
						System.out.println("SIGNED PAYMENT BY CLIENT: " + new String(encodeDecode.decryptWithPubKey(encodeDecode.decryptWithPubKey(verifying_Signature, my_pub_key_signature),publicKey_Client)));

						System.out.println(" CLIENT PAYMENT TO BE PAID TO WEB-SERVER :" + received_Payment);

						outputstream_Webserver.writeUTF(DES_EncDec_WebServer.encrypt(received_Payment));
						
						System.out.println("/*****************  **************************** ***************/ ");

						/*****************************************************************************************/

						/****************************** FORWARD PRODUCT ****************************/
						
						System.out.println("\n\n\n /*****************  FORWARD PRODUCT  ***************/ ");

						String encoded_Product = inputstream_Webserver.readUTF();

						String decoded_Product = DES_EncDec_WebServer.decrypt(encoded_Product);

						if (decoded_Product.equalsIgnoreCase("TRY AGAIN") == false){
							outputstream_Client.writeUTF(DES_EncDec_Client.encrypt(decoded_Product));
							
							int count, i=0;
							byte[] buffer = new byte[65535]; // or whatever you like really, not too small
							
							while (DES_EncDec_WebServer.decrypt(inputstream_Webserver.readUTF().trim()).equalsIgnoreCase("END")!=true)
							{
								System.out.println(" FORWARDING ENCRYPTED BYTES FROM WEB-SERVER " );
								
								outputstream_Client.writeUTF(DES_EncDec_Client.encrypt("START"));
								outputstream_Client.writeUTF(DES_EncDec_Client.encrypt(DES_EncDec_WebServer.decrypt(inputstream_Webserver.readUTF().trim())));
								
								i++;
							}
							
							//System.out.println("BROKER WAITING ON END ");
							
							outputstream_Client.writeUTF(DES_EncDec_Client.encrypt("END"));
							
							System.out.println("\n\n\n /*****************  END  ***************/ ");
							//outputstream_Client.writeUTF(DES_EncDec_Client.encrypt(DES_EncDec_WebServer.decrypt(inputstream_Webserver.readUTF())));
							
						}
						else {
							outputstream_Client.writeUTF(DES_EncDec_Client.encrypt("TRY AGAIN"));

							encoded_Payment = inputstream_Client.readUTF();

							decoded_Payment_Signature = DES_EncDec_Client.decrypt(encoded_Payment);
							received_Payment = decoded_Payment_Signature.split("\\|\\|")[1];

							
							
							System.out.println("\n\n\n /*****************  PAYMENT GATEWAY  ***************/ ");
							
							decoded_Array_Signature = decode_IncomingMessage.decodeBuffer(decoded_Payment_Signature
									.split("\\|\\|")[3]);

							decoded_withPriKey_Array = encodeDecode.decryptWithPubKey(decoded_Array_Signature,
									publicKey_Client);
							
							decoded_withPriKey_Array = encodeDecode.decryptWithPubKey(decoded_Array_Signature,publicKey_Client);
							
							signature_Encoded_Broker_priKey = encodeDecode.encryptWithPriKey(decoded_Array_Signature, my_private_key_signature);
							
							signature_File_write.write(signature_Encoded_Broker_priKey);
							
							verifying_Signature = new byte[signature_Encoded_Broker_priKey.length];
							
							System.out.println(" PAYMENT IS STORED BY ENCRYPTING WITH CLIENT PRIVTE KEY AND A SECOND PRIVATE KEY FROM BROKER ");
							
							signature_File_read.read(verifying_Signature);
							
							System.out.println(" SIGNATURE WRITTEN TO A FILE ");
							
							System.out.println("SIGNED PAYMENT BY CLIENT: " + new String(decoded_withPriKey_Array));

							System.out.println(" CLIENT PAYMENT :" + received_Payment);

							outputstream_Webserver.writeUTF(DES_EncDec_WebServer.encrypt(received_Payment));
							
							
							System.out.println("/*****************  **************************** ***************/ ");
							
							System.out.println("\n\n\n /*****************  FORWARD PRODUCT  ***************/ ");
							
							 encoded_Product = inputstream_Webserver.readUTF();

							 decoded_Product = DES_EncDec_WebServer.decrypt(encoded_Product);

							if (decoded_Product.equalsIgnoreCase("CANCEL") == false){
								outputstream_Client.writeUTF(DES_EncDec_Client.encrypt(decoded_Product));
								
								int count, i=0;
								byte[] buffer = new byte[65535]; // or whatever you like really, not too small
								
								while (DES_EncDec_WebServer.decrypt(inputstream_Webserver.readUTF().trim()).equalsIgnoreCase("END")!=true)
								{
									System.out.println(" FORWARDING ENCRYPTED BYTES FROM WEB-SERVER " );
									
									outputstream_Client.writeUTF(DES_EncDec_Client.encrypt("START"));
									outputstream_Client.writeUTF(DES_EncDec_Client.encrypt(DES_EncDec_WebServer.decrypt(inputstream_Webserver.readUTF().trim())));
									
									i++;
								}
								
								//System.out.println("BROKER WAITING ON END ");
								
								System.out.println("\n\n\n /*****************  END  ***************/ ");
								
								outputstream_Client.writeUTF(DES_EncDec_Client.encrypt("END"));
							}
							else
							{
								outputstream_Client.writeUTF(DES_EncDec_Client.encrypt("CANCEL"));
								System.out.println("WRONG PAYMENT AGAIN......... BROKER TERMINATED CONNECTION");
								
								System.out.println("\n\n\n /*****************  END  ***************/ ");
							}
						}
						/*************************************************************************/

					} else {
						System.out.println("FAILED TO LOGIN...");

						outputstream_Client.writeUTF(" HELLO " + clientSocket.getInetAddress().getHostName()
								+ " YOU ARE NOT AUTHENTICATED " + clientSocket.getLocalSocketAddress());
					}
				}

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block

				System.out.println("FAILED TO LOGIN...");

				try {
					outputstream_Client.writeUTF(" HELLO " + clientSocket.getInetAddress().getHostName()
							+ " YOU ARE NOT AUTHENTICATED " + clientSocket.getLocalSocketAddress());
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

}
