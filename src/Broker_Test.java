import java.beans.XMLEncoder;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
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
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Broker_Test implements Runnable {

	static String pubKeyFile;
	static String priKeyFile;
	static String User_PassFile;
	static String[] keyList;
	static KeyPair[] keyListPair = null;
	static PublicKey my_pub_key = null;
	static PrivateKey my_private_key = null;
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
	static Hashtable<String, Integer> User_Auth_NONCE = null;
	static Hashtable<String, Integer> User_Session_NONCE = null;

	static String userNames_Ebay[] = null;
	static String passWords_Ebay[] = null;
	static Hashtable<String, String> User_Pass_Ebay = null;

	static Hashtable<String, String> type_1 = null;
	static String[] type_1_Structure = null;

	static int recvd_msgType = 0;
	static String recvd_webServer = null;
	static String recvd_UserName = null;
	static String recvd_passWord = null;

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

	static DesEncrypter DES_EncDec_Client = null;
	static DesEncrypter DES_EncDec_WebServer = null;

	static DataInputStream inputstream_Client = null;
	static DataInputStream inputstream_Amazon = null;
	static DataInputStream inputstream_Ebay = null;
	static DataOutputStream outputstream_Client = null;
	static DataOutputStream outputstream_Amazon = null;
	static DataOutputStream outputstream_Ebay = null;

	static byte[] iv_WebServer = null;

	@SuppressWarnings("restriction")
	static BASE64Decoder decode_IncomingMessage = new BASE64Decoder();
	@SuppressWarnings("restriction")
	static BASE64Encoder encoder = new BASE64Encoder();

	static EncDec encodeDecode = new EncDec();
	static int ACCEPTED = 0;
	static Broker_Test test = null;

	public Broker_Test() {
		// TODO Auto-generated constructor stub
	}

	public void run() {
		// TODO Auto-generated method stub

		while (true) {
			if (Thread.currentThread().getName().equalsIgnoreCase("Receiver")) {
				System.out.println("RECEIVER THREAD RUNNING...");

				System.out.println("BROKER LISTENING FOR CLIENT...");

				try {
					clientSocket = serverSocket.accept();

					OutputStream outToClient = clientSocket.getOutputStream();
					outputstream_Client = new DataOutputStream(outToClient);

					Thread Reader = new Thread(test, "Reader");
					Reader.start();

					InputStream inFromServer = clientSocket.getInputStream();
					inputstream_Client = new DataInputStream(inFromServer);
					
					InputStream inFromAz = AmazonSocket.getInputStream();
					 inputstream_Amazon = new DataInputStream(inFromAz);

					InputStream inFromEb = EbaySocket.getInputStream();
					 inputstream_Ebay = new DataInputStream(inFromEb);
					
					OutputStream outToAz = AmazonSocket.getOutputStream();
					 outputstream_Amazon = new DataOutputStream(outToAz);

					OutputStream outToEb = EbaySocket.getOutputStream();
					 outputstream_Ebay = new DataOutputStream(outToEb);

					System.out.println("BROKER ACCEPTED CLIENT : " + clientSocket.getInetAddress().getHostName());

				}

				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

			if (Thread.currentThread().getName().equalsIgnoreCase("Reader")) {
				while (true) {

					System.out.println("READER THREAD RUNNING...");

					System.out
							.println("READER WAITING ON MESSAGES FROM " + clientSocket.getInetAddress().getHostName());
					
					String client_name = clientSocket.getInetAddress().getHostAddress();
					Integer port_number = clientSocket.getPort();

					try {
						String message_From_Client = inputstream_Client.readUTF();
						System.out.println("RECEIVED STRING : " + message_From_Client);

						String message_Header = message_From_Client.trim().split("\\|\\|")[0];

						String message_Body = message_From_Client.trim().split("\\|\\|", 2)[1];

						if (true == process_Body(message_Header, message_Body)) {
							System.out.println("APPROPRIATE MESSAGE");
						} else {
							// process_Body(message_Header, message_Body);
							System.out.println("INSUFFICIENT PARAMETERS.... MESSAGE MIGHT BE TAMPERED...");
						}

					} catch (IOException e) {
						// TODO Auto-generated catch block

						e.printStackTrace();

						System.out.println(" SENDER ENDED ");
						System.exit(1);

					} catch (InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (InvalidKeySpecException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IllegalBlockSizeException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (BadPaddingException e) {
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

	private boolean Authenticate(Hashtable<String, String> type, String msg_Body) {
		// TODO Auto-generated method stub

		String[] body = msg_Body.split("\\|\\|");

		recvd_webServer = body[0].trim();
		recvd_UserName = body[1].trim();
		recvd_passWord = body[2].trim();
		String recvd_NONCE = body[3].trim();
		String recvd_Digest = new String(body[4].trim());

		System.out.println(recvd_webServer + " " + recvd_UserName + " " + recvd_passWord + " " + recvd_NONCE + " "
				+ recvd_Digest);
		System.out.println(getDigest(recvd_webServer + "||" + recvd_UserName + "||" + recvd_passWord + "||" + "NONCE"));

		if (true == (recvd_Digest.equals(getDigest(recvd_webServer + "||" + recvd_UserName + "||" + recvd_passWord
				+ "||" + recvd_NONCE)))) {

			type.put(recvd_UserName, recvd_passWord);
			System.out.println("INITIALIZED STRUCTURE IS :");
			System.out.println(type);

			if (recvd_webServer.equalsIgnoreCase("Amazon") == true) {
				if ((type.get(recvd_UserName).equals(User_Pass_Amazon.get(recvd_UserName))) == true)
					return true;
				else {
					return false;
				}
			}

			else if (recvd_webServer.equalsIgnoreCase("Ebay") == true) {
				if ((type.get(recvd_UserName).equals(User_Pass_Ebay.get(recvd_UserName))) == true)
					return true;
				else {
					return false;
				}
			} else {
				return false;
			}
		} else {
			return false;
		}

	}

	@SuppressWarnings("restriction")
	private boolean process_Body(String message_Header, String message_Body) throws Exception {
		// TODO Auto-generated method stub

		switch (Integer.parseInt(message_Header.trim())) {
		case 1:

			Path path_Client = Paths.get("../Files/Client_pub_key.txt");
			byte[] keyBytes_Client = Files.readAllBytes(path_Client);

			System.out.println("READ BYTES OF PUBLIC KEY OF CLIENT IS: " + keyBytes_Client.length);

			publicKey_Client = encodeDecode.bytesToPubKey(keyBytes_Client);

			byte[] encoded_Authentication = decode_IncomingMessage.decodeBuffer(message_Body);

			System.out.println("DECODED BYTE SIZE OF PUB KEY ENCRYPTION: " + encoded_Authentication.length);

			byte[] decoded_PubKey_Auth = encodeDecode.decryptWithPubKey(encoded_Authentication, publicKey_Client);

			byte[] decoded_Authentication = encodeDecode.decryptWithPrivKey(decoded_PubKey_Auth, my_private_key);

			String client_Authentication = new String(decoded_Authentication);

			if (5 != client_Authentication.split("\\|\\|").length)
				return false;
			else {
				setMsgType(1);

				System.out.println();
				if (true == Authenticate(type_1, client_Authentication)) {

					System.out.println(" SUCCESSFULLY LOGGED IN !!!! ");

					outputstream_Client.writeUTF("1||" + " HELLO " + clientSocket.getInetAddress().getHostName()
							+ " YOU ARE AUTHENTICATED " + clientSocket.getLocalSocketAddress());
				}

				else {
					System.out.println("FAILED TO LOGIN...");

					outputstream_Client.writeUTF("1||" + " HELLO " + clientSocket.getInetAddress().getHostName()
							+ " YOU ARE NOT AUTHENTICATED " + clientSocket.getLocalSocketAddress());
				}

				return true;
			}

		case 2:

			/***********************************************************************************************/

			

				String Challenge = new String();
				String Challenge_Msg = new String();

				byte[] cipherText_byte = decode_IncomingMessage.decodeBuffer(message_Body);

				byte[] decrypted_array = encodeDecode.decryptWithPrivKey(cipherText_byte, my_private_key);

				// setMsgType(Integer.parseInt(new
				// String(decrypted_array).trim().split("\\|\\|")[0]));

				System.out.println("BRO-CLI RECEIVED MESSAGE TYPE :" + getMsgType());

				if (3 != new String(decrypted_array).trim().split("\\|\\|").length)
					return false;
				else {
					setMsgType(2);
					
					Challenge = new String(decrypted_array).trim().split("\\|\\|")[0];

			//	System.out.println(" STRING IN FORM OF BYTE ARRAY:" + Arrays.toString(decrypted_array));

				System.out.println("BRO-CLI RECEIVED CHALLENGE MESSAGE :" + Challenge);

			//	System.out.println("PROBABLE SESSION KEY BYTES:"+ Arrays.toString(decode_IncomingMessage.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[1])));

			//	byte[] sessionKey_byte = Arrays.copyOfRange(decrypted_array, 14, 30);

			//	System.out.println("SESSION KEY BYTE:" + Arrays.toString(sessionKey_byte));

				sessionKey_Cli_Bro = new SecretKeySpec(decode_IncomingMessage.decodeBuffer(new String(decrypted_array)
						.trim().split("\\|\\|")[1]), 0, decode_IncomingMessage.decodeBuffer(new String(decrypted_array)
						.trim().split("\\|\\|")[1]).length, "AES");

				DES_EncDec_Client = new DesEncrypter(sessionKey_Cli_Bro,
						decode_IncomingMessage.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[2]));

				String encrypted_Challenge = DES_EncDec_Client.encrypt(Challenge);

				outputstream_Client.writeUTF("2||" + encrypted_Challenge);
				outputstream_Client.flush();

			//	System.out.println("BYTES WRITTEN TILL NOW FROM BROKER :" + outputstream_Client.size());
			//	System.out.println("SENT BYTES LENGTH:" + encrypted_Challenge.getBytes().length);
			//	System.out.println("SENT BYTES :" + Arrays.toString(encrypted_Challenge.getBytes()));
			}
			/***********************************************************************************************/

		case 3:

			/***********************************************************************************************/

			setMsgType(3);

			System.out.println("BEFORE DES DECODING :" +Arrays.toString(message_Body.trim().getBytes()));
			
			String auth_WS_decoded = DES_EncDec_Client.decrypt(message_Body);
			
			System.out.println("AFTER DES DECODING :" +Arrays.toString(auth_WS_decoded.getBytes()));

			// setMsgType(Integer.parseInt(new
			// String(auth_WS_decoded).trim().split("\\|\\|")[0]));

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

			// byte[] tmp =
			// decode_IncomingMessage.decodeBuffer(auth_WS_decoded.trim().split("\\|\\|")[1]);

			outputstream_Webserver.writeUTF(auth_WS_decoded);

			//String reply_WebServer_Auth = inputstream_Webserver.readUTF();
			//outputstream_Client.writeUTF("3||" + reply_WebServer_Auth);
			
			return true;
			/***********************************************************************************************/
			
		case 11:
			outputstream_Client.writeUTF("3||" + DES_EncDec_Client.encrypt(message_Body));
			
			return true;
		}

		return false;
	}

	static void setMsgType(int type) {
		recvd_msgType = type;
	}

	static int getMsgType() {
		return recvd_msgType;
	}

	private boolean check_Body(String message_Header, String message_Body) {
		// TODO Auto-generated method stub

		switch (Integer.parseInt(message_Header.trim())) {
		case 1: // 1||Amazon||Mourya||HASH(PASSWORD)||NONCE||DIGEST
			// 5
			if (5 != message_Body.split("\\|\\|").length)
				return false;
			else {
				setMsgType(1);
				return true;
			}
		case 2: // 2||CHALLENGE||SESSION-KEY||IV||NONCE||DIGEST
			// 5
			if (5 != message_Body.split("\\|\\|").length)
				return false;
			else {
				setMsgType(2);
				return true;
			}
		case 3:
			// 3
			if (3 != message_Body.split("\\|\\|").length)
				return false;
			else {
				setMsgType(3);
				return true;
			}
		case 4:
			// 1
			if (1 != message_Body.split("\\|\\|").length)
				return false;
			else {
				setMsgType(4);
				return true;
			}
		case 5:
			// 1
			if (2 != message_Body.split("\\|\\|").length)
				return false;
			else {
				setMsgType(5);
				return true;
			}
		case 6:
			// 1
			if (3 != message_Body.split("\\|\\|").length)
				return false;
			else {
				setMsgType(6);
				return true;
			}
		default:
			return false;

		}

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

	public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		// TODO Auto-generated method stub

		pubKeyFile = "../Files/Broker_pub_key.txt";
		priKeyFile = "../Files/Broker_pri_key.txt";

		System.out.println(" BROKER PUBLIC KEY : CREATED");
		EncDec keygen = new EncDec();
		KeyPair pair = keygen.newKeyPair(1024);
		my_pub_key = pair.getPublic();
		my_private_key = pair.getPrivate();

		System.out.println(" BROKER PRIVATE KEY : CREATED");
		FileOutputStream key_writer = new FileOutputStream(pubKeyFile);
		key_writer.write(my_pub_key.getEncoded());
		key_writer.close();

		key_writer = new FileOutputStream(priKeyFile);
		key_writer.write(my_private_key.getEncoded());
		key_writer.close();

		System.out.println("CONNECTING TO... " + "net03.utdallas.edu" + " ON PORT " + portNumber_Amazon);

		AmazonSocket = new Socket("net03.utdallas.edu", portNumber_Amazon);
		System.out.println("JUST CONNECTED TO " + AmazonSocket.getInetAddress().getHostName());

		System.out.println("CONNECTING TO... " + "net04.utdallas.edu" + " ON PORT " + portNumber_Ebay);

		EbaySocket = new Socket("net04.utdallas.edu", portNumber_Ebay);
		System.out.println("JUST CONNECTED TO " + EbaySocket.getInetAddress().getHostName());
		
		/*
		 * Path path_Az = Paths.get("../Files/Amazon_pub_key.txt"); byte[]
		 * keyBytes_Az = Files.readAllBytes(path_Az);
		 * 
		 * publiKey_Amazon = encodeDecode.bytesToPubKey(keyBytes_Az);
		 * 
		 * Path path_Eb = Paths.get("../Files/Ebay_pub_key.txt"); byte[]
		 * keyBytes_Eb = Files.readAllBytes(path_Eb);
		 * 
		 * publiKey_Ebay = encodeDecode.bytesToPubKey(keyBytes_Eb);
		 */
		userNames_Amazon = new String[] { "Mourya", "kk", "Karthik", "RaviP" };
		passWords_Amazon = new String[] { "mourya", "kk", "karthik", "ravip" };

		userNames_Ebay = new String[] { "Mourya", "kk", "Karthik", "RaviP" };
		passWords_Ebay = new String[] { "mourya", "kk", "karthik", "ravip" };

		type_1 = new Hashtable<String, String>();

		User_Auth_NONCE = new Hashtable<String, Integer>();
		User_Session_NONCE = new Hashtable<String, Integer>();

		User_Pass_Amazon = new Hashtable<String, String>();
		User_Pass_Ebay = new Hashtable<String, String>();

		User_PassFile = "../Files/User_Pass.txt";

		createUserPassFile(User_Pass_Amazon, userNames_Amazon, passWords_Amazon);
		createUserPassFile(User_Pass_Ebay, userNames_Ebay, passWords_Ebay);

		serverSocket = new ServerSocket(portNumber_Broker);

		test = new Broker_Test();

		Thread Receiver = new Thread(test, "Receiver");

		Receiver.start();

	}

}
