import java.io.BufferedWriter;
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
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Amazon implements Runnable {

	static String pubKeyFile;
	static String priKeyFile;
	static String[] keyList;
	static PublicKey my_pub_key = null;
	static PrivateKey my_private_key = null;
	static KeyPair[] keyListPair = null;
	static ServerSocket serverSocket = null;
	static int portNumber_Broker = 7354;
	static int portNumber_Amazon = 18353;
	static Socket clientSocket = null;
	
	static PublicKey publicKey_Broker = null;
	 
	 
	static XmlParser parseXML = new XmlParser();
    static String product_List = new String();
    static String key_for_Encrypt_File = "Mary has one cat";
	static File inputFile_for_Encrypt_File = new File("../Files/Amazon_Products.xml");
	static File encryptedFile_for_Encrypt_File = new File("../Files/Amazon_Products.xml");
	static int recvd_msgType;  
	
	@SuppressWarnings("restriction")
	static BASE64Encoder encoder = new BASE64Encoder();
	
	static EncDec encodeDecode = new EncDec();

	static BASE64Decoder decode_IncomingMessage = new BASE64Decoder();
	static EncryptFile encFile = new EncryptFile();
	/*
	 * public Amazon() { // TODO Auto-generated constructor stub
	 * 
	 * pubKeyFile = "Amazon_pub_key.txt"; priKeyFile = "Amazon_pri_key.txt";
	 * keyList = new KeyGenerator().generate(); }
	 */
	static void setMsgType(int type) {
		recvd_msgType = type;
	}

	static int getMsgType() {
		return recvd_msgType;
	}
	
	static String readFile(String path, Charset encoding) 
			  throws IOException 
			{
			  byte[] encoded = Files.readAllBytes(Paths.get(path));
			  return new String(encoded, encoding);
			}
	
	public static void main(String[] args) throws IOException,
			NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, CryptoException {
		// TODO Auto-generated method stub

		// *********************************************** PUBLIC PRIVATE KEY
		// GEN START ************************************************//

		pubKeyFile = "../Files/Amazon_pub_key.txt";
		priKeyFile = "../Files/Amazon_pri_key.txt";

		System.out.println(" AMAZON PUBLIC KEY : CREATED");
		EncDec keygen = new EncDec();
		KeyPair pair = keygen.newKeyPair(1024);
		my_pub_key = pair.getPublic();
		my_private_key = pair.getPrivate();

		System.out.println(" AMAZON PRIVATE KEY : CREATED");
		FileOutputStream key_writer = new FileOutputStream(pubKeyFile);
		key_writer.write(my_pub_key.getEncoded());
		key_writer.close();

//		key_writer = new FileOutputStream(priKeyFile);
//		key_writer.write(my_private_key.getEncoded());
//		key_writer.close();
//	

		System.out.println(" /*****************  PUBLIC KEY PAIR GENERATION ***************/ ");
		
		System.out.println(" ALGORITHM USED     : RSA" );
		System.out.println(" KEY LENGTH         : 1024 BITS");
		System.out.println(" CHAINING ALGORITHM : ECB");
		System.out.println(" PADDING            : NO PADDING");
		
		System.out.println(" /*****************  *************** ***************/ ");
		
		//encFile.encrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
		// *********************************************** PUBLIC PRIVATE KEY
		// GEN END ************************************************//

		serverSocket = new ServerSocket(portNumber_Amazon);

		(new Thread(new Amazon())).start(); // START RECEIVE THREAD

		String serverName = ManagementFactory.getRuntimeMXBean().getName();
		System.out.println("MY NAME : " + serverName.split("@")[1]);

		/*
		 * System.out.println("CONNECTING TO... " + "net02.utdallas.edu" +
		 * " ON PORT " + portNumber_Broker);
		 * 
		 * @SuppressWarnings("resource") Socket Broker = new
		 * Socket("net02.utdallas.edu", portNumber_Broker);
		 * System.out.println("JUST CONNECTING TO "+
		 * Broker.getRemoteSocketAddress());
		 */
	}

	@SuppressWarnings({ "restriction", "resource" })
	public void run() {
		// TODO Auto-generated method stub
		 List<String> client_nonce_list = new ArrayList<String>();
		 List<String> broker_nonce_list = new ArrayList<String>();
		 
		while (true) {
			System.out.println("AMAZON LISTENING ON PORT" + portNumber_Amazon
					+ " ...");

			try {
				clientSocket = serverSocket.accept();

				InputStream inFromServer = clientSocket.getInputStream();
				DataInputStream in = new DataInputStream(inFromServer);
				 
				OutputStream outToClient = clientSocket.getOutputStream();
		        DataOutputStream out = new DataOutputStream(outToClient);
		        		       

				System.out.println("AMAZON ACCEPTED : "
						+ clientSocket.getInetAddress().getHostName());

				String client_id = clientSocket.getInetAddress().getHostName() + String.valueOf(clientSocket.getPort());
				
				System.out.println(" /*****************  WEB-SERVER/CLIENT SESSION-KEY EXCHANGE ***************/ ");
				
				
				String Challenge_Msg = new String();

				Challenge_Msg = in.readUTF();
				
			//	System.out.println("BEFORE BASE 64 DECODING :" +Arrays.toString(Challenge_Msg.trim().getBytes()));
				
				byte[] cipherText_byte = decode_IncomingMessage.decodeBuffer(Challenge_Msg.trim());
				
				//System.out.println("BRO-AMAZON LENGTH BEFORE DECODING :" + cipherText_byte.length);
			
			//	System.out.println("BRO-AMAZON : ARRAY TO BYTES OUTPUT STREAM ARRAY: "+ Arrays.toString(cipherText_byte));
				
				byte[] decrypted_array = encodeDecode.decryptWithPrivKey(cipherText_byte,my_private_key);		
				
				//System.out.println("SESSION KEY CREATED BY CLIENT IN FROM OF BYTES:"+ Arrays.toString((new String(decrypted_array).trim().split("\\|\\|")[0]).getBytes()));
				
			//	System.out.println("DECODED SECRET FOR WEB SERVER BYTES:"+Arrays.toString(decrypted_array));
				
				SecretKey originalKey = new SecretKeySpec(decode_IncomingMessage.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[0]), 0, decode_IncomingMessage.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[0]).length, "AES");
				
				DesEncrypter Session_Client_Amazon_EncDec = new DesEncrypter(originalKey, decode_IncomingMessage.decodeBuffer(new String(decrypted_array).trim().split("\\|\\|")[1]));
				
				String client_nonce = new String(decrypted_array).trim().split("\\|\\|")[2];
				
				String Challenge_from_Client = new String(decrypted_array).trim().split("\\|\\|")[3];
				
				if(!client_nonce_list.contains(client_id+client_nonce))
				{
				
					client_nonce_list.add(client_id+client_nonce);
				}
				
				else
				{
					System.out.println("replay attack !!!!....aborting program!!!");
					System.exit(0);
				}
				//SecretKey originalKey = new SecretKeySpec(decrypted_array, 0, decrypted_array.length, "AES");
				
				//DesEncrypter Session_EncDec = new DesEncrypter(originalKey);
				
				out.writeUTF(Session_Client_Amazon_EncDec.encrypt(Challenge_from_Client));
				
				
				/*********************/
				
				String Challenge_Msg_Broker = new String(); 											
				
				
				Challenge_Msg_Broker = in.readUTF();
				
				
				byte[] cipherText_byte_Broker = decode_IncomingMessage.decodeBuffer(Challenge_Msg_Broker);
				
				//System.out.println("BRO-CLI LENGTH BEFORE DECODING :" + cipherText_byte_Broker.length);
				
				Path path = Paths.get("../Files/Broker_pub_key.txt");
		        byte[] keyBytes = Files.readAllBytes(path);

		        publicKey_Broker = encodeDecode.bytesToPubKey(keyBytes);
			
				//byte[] decrypted_array_Broker = encodeDecode.decryptWithPubKey(encodeDecode.decryptWithPrivKey(cipherText_byte_Broker,my_private_key), publicKey_Broker); 
				
				byte[] decrypted_Auth_Pri_array = encodeDecode.decryptWithPubKey(cipherText_byte_Broker, publicKey_Broker);
				
				byte[] decrypted_array_Broker = encodeDecode.decryptWithPrivKey(decrypted_Auth_Pri_array, my_private_key);
				
				//System.out.println("BRO-CLI ARRAY TO BYTES DECRYPTED ARRAY: "+Arrays.toString(decrypted_array_Broker));
				
			//	System.out.println("BRO-CLI ARRAY REPRESENTED AS STRING AFTER DECODING :" + new String(decrypted_array_Broker).trim());
				
				setMsgType(Integer.parseInt(new String(decrypted_array_Broker).trim().split("\\|\\|")[0]));
				
				//System.out.println("BRO-CLI RECEIVED MESSAGE TYPE :" + getMsgType());
				
				String Challenge = new String(decrypted_array_Broker).trim().split("\\|\\|")[1]; 
				
				//System.out.println("BRO-CLI RECEIVED CHALLENGE MESSAGE :"+ Challenge);
				
				//System.out.println("BRO-CLI SESSION KEY :"+ new String(decrypted_array).trim().split("\\|\\|")[2]+":");
				
				//byte[] sessionKey_byte = Arrays.copyOfRange(decrypted_array_Broker, 14, 30);
				
				//byte[] sessionKey_byte  = decode_IncomingMessage.decodeBuffer(new String(decrypted_array));
				
				//System.out.println("BRO-CLI ARRAY TO BYTES SESSION ARRAY: "+ Arrays.toString(sessionKey_byte));
				
				//System.out.println("BRO-CLI LENGTH AFTER DECODING :" + sessionKey_byte.length);
				
				SecretKey sessionKey_Broker_Amazon = new SecretKeySpec(decode_IncomingMessage.decodeBuffer(new String(decrypted_array_Broker).trim().split("\\|\\|")[2]), 0, decode_IncomingMessage.decodeBuffer(new String(decrypted_array_Broker).trim().split("\\|\\|")[2]).length, "AES");
				
				DesEncrypter Session_Broker_Amazon_EncDec = new DesEncrypter(sessionKey_Broker_Amazon, decode_IncomingMessage.decodeBuffer(new String(decrypted_array_Broker).trim().split("\\|\\|")[3]));
				
				String broker_nonce = new String(decrypted_array_Broker).trim().split("\\|\\|")[3];
				
				if(!broker_nonce_list.contains(broker_nonce) || broker_nonce_list == null)
				{
				
					broker_nonce_list.add(broker_nonce);
				}
				
				else 
				{
					System.out.println("replay attack!!!!......aborting program!!");
					System.exit(0);
				}
				
				out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(Challenge));
				
				/*********************/
				
				/******************************* SENDING PRODUCT CATALOGUE ***************************/
				
				String product_catalog_request = in.readUTF();
				
				String decrypted_product = Session_Client_Amazon_EncDec.decrypt(Session_Broker_Amazon_EncDec.decrypt(product_catalog_request));
				
				System.out.println("PRODUCT CATALOGUE REQUEST RECEIVED IS :"+ decrypted_product);
				
				
				//encFile.decrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
				
				product_List = parseXML.getString("../Files/Amazon_Products.xml", decrypted_product);
				
				//encFile.encrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
				
				out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(Session_Client_Amazon_EncDec.encrypt(product_List)));
				
				/***********************************************************************************/
				
				/******************************* SENDING PRODUCT CATALOGUE ***************************/
					
				String endoded_product_ID_selected = in.readUTF();
				
				String decoded_product_ID_selected = Session_Broker_Amazon_EncDec.decrypt(endoded_product_ID_selected);
				
				System.out.println(" CLIENT SELECTED PRODUCT ID:"+ decoded_product_ID_selected);
				
				/************************************************************************************/
				
				/******************************* FINDING PRODUCT PRODUCT ******************************/
				
				String selected_line_item = new String(); 
				
				for(String each : product_List.split("\\|\\|"))
				{
					if(each.contains(decoded_product_ID_selected)==true)
					{
						selected_line_item = each; 
						break;
					}
				}
				
		
				
				/************************************************************************************/
				
				
				/******************************* FINAL PAYMENT ******************************/
				
				String encoded_final_payment = in.readUTF();
				
				String decoded_final_payment = Session_Broker_Amazon_EncDec.decrypt(encoded_final_payment);
				
				System.out.println(" PAYMENT RECEIVED BY BROKER : "+decoded_final_payment);
				
				/*****************************************************************************/
				
				/******************************* PAYMENT CONFIRMATION ******************************/
				
				if(selected_line_item.split(":")[2].equals("$"+decoded_final_payment)==true)
				{
					System.out.println(" APPROVED FINAL PAYMENT :) :) :) ");
					
					/******************************* SENDING PRODUCT ******************************/
					
					String PRODUCT = selected_line_item.split(":")[1]; 
					out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(Session_Client_Amazon_EncDec.encrypt(PRODUCT)));
					
					 File inputFile = new File("../Files/"+PRODUCT);
					 File encryptedFile = new File("../Files/encypted_audio");
					
					encFile.encrypt(originalKey, inputFile, encryptedFile);
					
					FileInputStream readeFile = new FileInputStream("../Files/encypted_audio");

					int count=0;
					int buffer_size = 30000; 
					byte[] buffer = new byte[buffer_size]; // or wbyte[] small_buffer = new byte[5000];
					
					while ((count = readeFile.read(buffer)) != -1)
					{
					  // out.write(buffer, 0, count);
						System.out.println("READ BYTES: "+ count);
						out.writeUTF(Session_Broker_Amazon_EncDec.encrypt("START"));
						//out.writeUTF(Session_Client_Amazon_EncDec.encrypt(encoder.encode(buffer)));
						if(count>=buffer_size)
							out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(encoder.encode(buffer)));
						else
						{
							byte[] small_buffer = new byte[count];
							small_buffer = Arrays.copyOfRange(buffer, 0, count);
							out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(encoder.encode(small_buffer)));
							
						}
					}
					   //out.writeUTF(Session_Client_Amazon_EncDec.encrypt("END"));
					TimeUnit.SECONDS.sleep(1);
					   out.writeUTF(Session_Broker_Amazon_EncDec.encrypt("END"));
					 
					  
					
					/******************************************************************************/
				}
				else
				{
					System.out.println(" DID NOT RECEIVE APPROPRITATE PAYMENT :( :( :(");
					System.out.println(" EXPECTED :" + selected_line_item.split(":")[2]);
					System.out.println(" RECEIVED :" + decoded_final_payment);
					
					out.writeUTF(Session_Broker_Amazon_EncDec.encrypt("TRY AGAIN"));
					
					 encoded_final_payment = in.readUTF();
					
					 decoded_final_payment = Session_Broker_Amazon_EncDec.decrypt(encoded_final_payment);
					
					System.out.println(" PAYMENT RECEIVED BY BROKER : "+decoded_final_payment);
					
					if(selected_line_item.split(":")[2].equals("$"+decoded_final_payment)==true)
					{
						System.out.println(" APPROVED FINAL PAYMENT :) :) :) ");
						
						/******************************* SENDING PRODUCT ******************************/
						
						String PRODUCT = selected_line_item.split(":")[1]; 
						out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(Session_Client_Amazon_EncDec.encrypt(PRODUCT)));
						
						
						 File inputFile = new File("../Files/"+PRODUCT);
						 File encryptedFile = new File("../Files/encypted_audio");
						
						encFile.encrypt(originalKey, inputFile, encryptedFile);
						
						FileInputStream readeFile = new FileInputStream("../Files/encypted_audio");

						int count=0;
						int buffer_size = 30000; 
						byte[] buffer = new byte[buffer_size]; // or wbyte[] small_buffer = new byte[5000];
						
						while ((count = readeFile.read(buffer)) != -1)
						{
						  // out.write(buffer, 0, count);
							System.out.println("READ BYTES: "+ count);
							out.writeUTF(Session_Broker_Amazon_EncDec.encrypt("START"));
							//out.writeUTF(Session_Client_Amazon_EncDec.encrypt(encoder.encode(buffer)));
							if(count>=buffer_size)
								out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(encoder.encode(buffer)));
							else
							{
								byte[] small_buffer = new byte[count];
								small_buffer = Arrays.copyOfRange(buffer, 0, count);
								out.writeUTF(Session_Broker_Amazon_EncDec.encrypt(encoder.encode(small_buffer)));
								
							}
						}
						   //out.writeUTF(Session_Client_Amazon_EncDec.encrypt("END"));
						TimeUnit.SECONDS.sleep(1);
						   out.writeUTF(Session_Broker_Amazon_EncDec.encrypt("END"));
						
						/******************************************************************************/
					}
					else
					{
						out.writeUTF(Session_Broker_Amazon_EncDec.encrypt("CANCEL"));
					}
				}
				
				
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
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