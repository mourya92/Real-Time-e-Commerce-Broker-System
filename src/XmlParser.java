import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

	
public class XmlParser {


	static String key_for_Encrypt_File = "Mary has one cat";
	static File inputFile_for_Encrypt_File = new File("Files/test.xml");
	static File encryptedFile_for_Encrypt_File = new File("Files/test.xml");
	static EncryptFile encFile = new EncryptFile();

	public String getString(String file_name, String tag) {
		String return_String = new String();
		try {
			File inputFile = new File(file_name);
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder;

			dBuilder = dbFactory.newDocumentBuilder();

			Document doc = dBuilder.parse(inputFile);
			doc.getDocumentElement().normalize();

			XPath xPath = XPathFactory.newInstance().newXPath();
			
			 
			
			String expression = "/inventory/category[@type='"+tag+"']";
			NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(doc, XPathConstants.NODESET);
			
			for (int i = 0; i < nodeList.getLength(); i++) {
				
				Node nNode = nodeList.item(i);
			//	System.out.println("\nCurrent Element :" + nNode.getNodeName());
				
				return_String +="||";
				
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
					Element eElement = (Element) nNode;
				/*	System.out.println("Student roll no : " + eElement.getAttribute("rollno"));
					System.out.println("ID : " + eElement.getElementsByTagName("id").item(0).getTextContent());
					System.out.println("NAME : " + eElement.getElementsByTagName("name").item(0).getTextContent());
					System.out.println("PRICE : " + eElement.getElementsByTagName("price").item(0).getTextContent());
				*/	
					return_String += eElement.getElementsByTagName("id").item(0).getTextContent() + ":" 
									+ eElement.getElementsByTagName("name").item(0).getTextContent() + ":"
									+ eElement.getElementsByTagName("price").item(0).getTextContent();
				}
				 
					
			}
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		
		if(return_String.isEmpty()==true)
			return "NO ITEMS";
		else
			return return_String.split("\\|\\|", 2)[1];
	}

	public static void main(String[] args) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, CryptoException, IOException {
			
			String tag = "Movies";
			
			//encFile.encrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
			
			
			//encFile.decrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
			
			//product_List = parseXML.getString("../Files/Amazon_Products.xml", decrypted_product);
			
			//encFile.encrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
			
			
			XmlParser parsexml = new XmlParser();
			//encFile.decrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
			System.out.println(parsexml.getString("Files/test.xml", tag));
			//encFile.encrypt(key_for_Encrypt_File,inputFile_for_Encrypt_File, encryptedFile_for_Encrypt_File);
	}
}