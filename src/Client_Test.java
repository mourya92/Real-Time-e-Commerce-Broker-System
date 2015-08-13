import java.beans.XMLEncoder;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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
import java.net.UnknownHostException;
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

public class Client_Test implements Runnable {

	static String pubKeyFile;
	static String priKeyFile;
	static byte[] keyList;
	static String webServer = null;
	static ServerSocket serverSocket = null;
	static int portNumber_Broker = 17354;
	static Socket clientSocket = null;
	static int Broker_connected = 0;
	static Socket socket_for_Broker = null;
	static PublicKey my_pub_key = null;
	static PrivateKey my_private_key = null;
	static SecretKey sessionKey_Broker = null;
	static SecretKey sessionkey_WebServer = null;
	static PublicKey publicKey_Broker = null;
	static PublicKey publicKey_WebServer = null;
	static String prodCatRequest = null;
	static EncDec encodeDecode = new EncDec();
	@SuppressWarnings("restriction")
	static BASE64Encoder encoder = new BASE64Encoder();

	static InputStream inFromBroker = null;
	static DataInputStream stream_Broker = null;
	static DesEncrypter DES_EncDec_Broker = null;
	static DesEncrypter DES_EncDec_WebServer = null;

	static byte[] iv_Broker = null;
	static byte[] iv_WebServer = null;

	public Client_Test() {
		// TODO Auto-generated constructor stub
	}

	public void run() {
		// TODO Auto-generated method stub

		while (true) {
			if (Thread.currentThread().getName().equalsIgnoreCase("Receiver")) {
				System.out.println("RECEIVER THREAD RUNNING...");

				System.out.println("CLIENT LISTENING...");

				try {
					clientSocket = serverSocket.accept();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				System.out.println("CLIENT ACCEPTED : " + clientSocket.getInetAddress());
			}

			if (Thread.currentThread().getName().equalsIgnoreCase("Reader")) {
				System.out.println("READER THREAD RUNNING...");

				try {
					String msgFromBroker = stream_Broker.readUTF();
					System.out.println("RECEIVED STRING : " + msgFromBroker);

					String message_Header = msgFromBroker.trim().split("\\|\\|")[0];

					String message_Body = msgFromBroker.trim().split("\\|\\|", 2)[1];

					if (true == process_Body(message_Header, message_Body)) {
						System.out.println("APPROPRIATE MESSAGE");
					}

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();

					System.out.println(" SENDER ENDED ");
					System.exit(1);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

	}

	// *********************************************** PUBLIC PRIVATE KEY GEN
	// START ************************************************//

	private boolean process_Body(String message_Header, String message_Body) throws Exception {
		// TODO Auto-generated method stub

		switch (Integer.parseInt(message_Header.trim())) {
		case 1:
			if (1 != message_Body.split("\\|\\|").length)
				return false;
			else 
			{	
				if (message_Body.contains("NOT") == true) {
				System.out.println(" I AM NOT AUTHENTICATED :( ");
				System.exit(1);
				return true;

				}

			if (message_Body.contains("NOT") == false) {
				SecureRandom random_Broker = new SecureRandom();
				iv_Broker = new byte[16];
				random_Broker.nextBytes(iv_Broker);

				sessionKey_Broker = new KeyGen().getSessionKey();
				DES_EncDec_Broker = new DesEncrypter(sessionKey_Broker, iv_Broker);

				// DES_EncDec_Broker = new DesEncrypter(sessionKey_Broker);
				byte[] share_SessionKey_Broker_Client = share_SessionKey_Broker_Client("CHALLENGE");

				send_Message("2||", share_SessionKey_Broker_Client);
			}
				return true;
			}
			
		case 2: 
			
				String decoded_Challenge = DES_EncDec_Broker.decrypt(message_Body); 
				
				System.out.println("DECODED CHALLENGE MESSAGE IS :"+ decoded_Challenge);
				
				if (1 != message_Body.split("\\|\\|").length)
					return false;
				else
				{
				if(decoded_Challenge.equals("CHALLENGE")==true)
				{
					System.out.println(" BROKER AUTHENTICATED ");
					
					/*************************************************** SHARING SESSION KEY BETWEEN WEBSERVER-CLIENT ************************/
					SecureRandom random_WebServer = new SecureRandom();
					  iv_WebServer = new byte[16];
					  random_WebServer.nextBytes(iv_WebServer);
					  
					if(webServer.equalsIgnoreCase("Amazon")==true)
					{
						sessionkey_WebServer = new KeyGen().getSessionKey();
						DES_EncDec_WebServer = new DesEncrypter(sessionkey_WebServer, iv_WebServer);
						
						Path path_Az = Paths.get("../Files/Amazon_pub_key.txt");
				        byte[] keyBytes_Az = Files.readAllBytes(path_Az);

				        publicKey_WebServer = encodeDecode.bytesToPubKey(keyBytes_Az);
				        
					}
					if(webServer.equalsIgnoreCase("Ebay")==true)
					{
						sessionkey_WebServer = new KeyGen().getSessionKey();
						DES_EncDec_WebServer = new DesEncrypter(sessionkey_WebServer, iv_WebServer);
						
						Path path_Eb = Paths.get("../Files/Ebay_pub_key.txt");
				        byte[] keyBytes_Eb = Files.readAllBytes(path_Eb);

				        publicKey_WebServer = encodeDecode.bytesToPubKey(keyBytes_Eb);
				        
					}
					
					String auth_WebServer = share_SessionKey_WebServer_Client("CHALLENGE"); 
					
					
					send_Message("3||",auth_WebServer);
					
					return true;
			}
		}
				
		case 3:
			
			String decoded_WS_Challenge = DES_EncDec_WebServer.decrypt(DES_EncDec_Broker.decrypt(message_Body));
			
			System.out.println("DECODED REPLY FROM WEB SERVER CHALLENGE MESSAGE :"+ decoded_WS_Challenge);
		
	}
		return false;
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
			
			byte[] Encoded_sessionKey_WebServer_byte = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publicKey_WebServer);
			
			System.out.println("ENCODED SECRET FOR WEB SERVER BYTES:"+Arrays.toString(Encoded_sessionKey_WebServer_byte));
			
			System.out.println("AFTER BASE_64 ENCODING :" +Arrays.toString(encoder.encode(Encoded_sessionKey_WebServer_byte).getBytes()));
			
			String auth_WebServer = DES_EncDec_Broker.encrypt(challenge_Msg_WebServer + encoder.encode(Encoded_sessionKey_WebServer_byte));		
			
			System.out.println("AFTER DES ENCODING :" +Arrays.toString(auth_WebServer.getBytes()));
			
			return auth_WebServer;
	}

	@SuppressWarnings("restriction")
	private static byte[] share_SessionKey_Broker_Client(String challenge_Msg) throws Exception {
		// TODO Auto-generated method stub

		byte[] sessionKey_Broker_byte = sessionKey_Broker.getEncoded();

		System.out.println("AES KEY IN BYTE ARRAY:" + Arrays.toString(sessionKey_Broker_byte));

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		outputStream.write(("CHALLENGE||").getBytes());
		outputStream.write(encoder.encode(sessionKey_Broker_byte).getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(encoder.encode(iv_Broker).getBytes());

		byte[] challenge_Broker = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publicKey_Broker);

		System.out.println("BYTE ARRAY OF CHALLANGE||AES KEY :" + Arrays.toString(outputStream.toByteArray()));
		return challenge_Broker;
	}

	private static void create_Public_Private() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		// TODO Auto-generated method stub

		pubKeyFile = "../Files/Client_pub_key.txt";
		priKeyFile = "../Files/Client_pri_key.txt";

		EncDec keygen = new EncDec();
		KeyPair pair = keygen.newKeyPair(1024);

		Path path = Paths.get("../Files/Broker_pub_key.txt");
		byte[] keyBytes = Files.readAllBytes(path);

		publicKey_Broker = encodeDecode.bytesToPubKey(keyBytes);

		System.out.println("RETRIEVED PUBLIC KEY OF BROKER :" + publicKey_Broker);

		my_pub_key = pair.getPublic();
		my_private_key = pair.getPrivate();

		System.out.println(" CLIENT PUBLIC KEY : CREATED");
		FileOutputStream key_writer = new FileOutputStream(pubKeyFile);
		key_writer.write(my_pub_key.getEncoded());
		key_writer.close();

		System.out.println(" CLIENT PRIVATE KEY : CREATED");
		key_writer = new FileOutputStream(priKeyFile);
		key_writer.write(my_private_key.getEncoded());
		key_writer.close();

	}

	// *********************************************** PUBLIC PRIVATE KEY GEN
	// END ************************************************//

	private static void get_authenticated(String webServer, String userName, String passWord) throws IOException,
			NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException {
		// TODO Auto-generated method stub

		MessageDigest md;
		md = MessageDigest.getInstance("MD5");
		md.update(passWord.getBytes());

		byte byteData[] = md.digest();

		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			String hex = Integer.toHexString(0xff & byteData[i]);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}

		/****************************/

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		outputStream.write((webServer + "||" + userName + "||" + hexString.toString()).getBytes());
		// outputStream.write(encoder.encode(sessionKey_Broker_byte).getBytes());
		outputStream.write(("||").getBytes());
		// outputStream.write(encoder.encode(iv_Broker).getBytes());
		outputStream.write(("NONCE").getBytes());
		outputStream.write(("||").getBytes());
		outputStream.write(getDigest(webServer + "||" + userName + "||" + hexString.toString() + "||" + "NONCE")
				.getBytes());

		System.out.println(webServer + " " + userName + " " + hexString.toString() + " " + "NONCE" + " "
				+ getDigest(webServer + "||" + userName + "||" + hexString.toString() + "||" + "NONCE"));

		System.out.println("ENCODING BYTE SIZE : " + outputStream.toByteArray().length);

		byte[] pubKey_encoding_Auth = encodeDecode.encryptWithPubKey(outputStream.toByteArray(), publicKey_Broker);

		System.out.println("ENCODING BYTE SIZE OF PUB KEY ENCRYPTION: " + pubKey_encoding_Auth.length);

		byte[] authenticate_Client = encodeDecode.encryptWithPriKey(pubKey_encoding_Auth, my_private_key);

		send_Message("1||", authenticate_Client);

		/****************************/

		// String message = webServer+"||"+userName+"||"+hexString.toString();
		// send_Message(1, message);
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

	private static void send_Message(String Msg_type, byte[] msg) throws IOException {

		OutputStream outToBroker = socket_for_Broker.getOutputStream();
		DataOutputStream out = new DataOutputStream(outToBroker);

		@SuppressWarnings("restriction")
		String msg_send = encoder.encode(msg);

		out.writeUTF(Msg_type + msg_send);
	}

	private static void send_Message(String Msg_type, String msg) throws IOException {
		// TODO Auto-generated method stub
		
		OutputStream outToBroker = socket_for_Broker.getOutputStream();
        DataOutputStream out = new DataOutputStream(outToBroker);
         
        out.writeUTF(Msg_type +msg);
        
      //  System.out.println("CLIENT SENT MESSAGE :"+msg);
		
	}
	
	public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException {
		// TODO Auto-generated method stub

		Client_Test test = new Client_Test();

		Thread Receiver = new Thread(test, "Receiver");
		Thread Reader = new Thread(test, "Reader");

		socket_for_Broker = new Socket("net02.utdallas.edu", portNumber_Broker);
		System.out.println("JUST CONNECTED TO " + socket_for_Broker.getInetAddress().getHostName());

		inFromBroker = socket_for_Broker.getInputStream();
		stream_Broker = new DataInputStream(inFromBroker);

		OutputStream outToBroker = socket_for_Broker.getOutputStream();
		DataOutputStream out = new DataOutputStream(outToBroker);

		serverSocket = new ServerSocket(portNumber_Broker);

		Receiver.start();
		Reader.start();

		while (true) {

			create_Public_Private();

			System.out.println("PLEASE ENTER WEB SERVER : ");
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			webServer = br.readLine();

			System.out.println("PLEASE ENTER USER NAME : ");
			br = new BufferedReader(new InputStreamReader(System.in));
			String userName = br.readLine();

			System.out.println("PLEASE ENTER PASSWORD : ");
			br = new BufferedReader(new InputStreamReader(System.in));
			String passWord = br.readLine();

			get_authenticated(webServer, userName, passWord);

			System.out.println("PLEASE ENTER PRODUCT REQUEST : ");
			br = new BufferedReader(new InputStreamReader(System.in));
			String prodCatRequest = br.readLine();

			out.writeUTF(prodCatRequest);
		}
	}

}
