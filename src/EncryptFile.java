import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A utility class that encrypts or decrypts a file.
 * 
 * @author www.codejava.net
 *
 */

public class EncryptFile {
	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

	public void encrypt(SecretKey key, File inputFile, File outputFile) throws CryptoException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			IOException, InvalidAlgorithmParameterException {
		doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
	}

	public void decrypt(SecretKey key, File inputFile, File outputFile) throws CryptoException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			IOException, InvalidAlgorithmParameterException {
		doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
	}

	public void encrypt(String key, File inputFile, File outputFile) throws CryptoException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			IOException, InvalidAlgorithmParameterException {
		doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
	}

	public void decrypt(String key, File inputFile, File outputFile) throws CryptoException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			IOException, InvalidAlgorithmParameterException {
		doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
	}

	private static void doCrypto(int cipherMode, String key, File inputFile, File outputFile) throws CryptoException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IOException, InvalidAlgorithmParameterException {

		byte[] iv = { 59, -109, -11, -22, -3, -121, -86, 31, 103, -18, 71, -2, -46, 68, 91, 123 };
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(cipherMode, secretKey, ivParameterSpec);

		FileInputStream inputStream = new FileInputStream(inputFile);
		byte[] inputBytes = new byte[(int) inputFile.length()];
		inputStream.read(inputBytes);

		byte[] outputBytes = cipher.doFinal(inputBytes);

		FileOutputStream outputStream = new FileOutputStream(outputFile);
		outputStream.write(outputBytes);

		inputStream.close();
		outputStream.close();

	}

	private static void doCrypto(int cipherMode, SecretKey key, File inputFile, File outputFile)
			throws CryptoException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException {
		// SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
		byte[] iv = { 59, -109, -11, -22, -3, -121, -86, 31, 103, -18, 71, -2, -46, 68, 91, 123 };
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(cipherMode, key, ivParameterSpec);
		//cipher.init(cipherMode, key);
		
		FileInputStream inputStream = new FileInputStream(inputFile);
		byte[] inputBytes = new byte[(int) inputFile.length()];
		inputStream.read(inputBytes);

		byte[] outputBytes = cipher.doFinal(inputBytes);

		FileOutputStream outputStream = new FileOutputStream(outputFile);
		outputStream.write(outputBytes);

		inputStream.close();
		outputStream.close();

	}

	static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}

	public static void main(String[] args) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException {
		String key = "Mary has one cat";
		File inputFile = new File("Files/Test.wma");
		File encryptedFile = new File("Files/Encrypted_Test");
		File decryptedFile = new File("Files/Out.wma");
		EncDec encdec = new EncDec();

		try {
			new EncryptFile().encrypt(key, inputFile, encryptedFile);

			String encrypted_File_String = readFile("Files/Encrypted_Test", StandardCharsets.UTF_8);

			int quotient = encrypted_File_String.getBytes().length / 1000;

			int reminder = encrypted_File_String.getBytes().length % 1000;

			System.out.println(" LENGTH :" + encrypted_File_String.getBytes().length + " QUO:" + quotient + " REM:"
					+ reminder);

			byte[] original = new byte[1000];
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			int i = 0, from = 0, to = 1000;

			original = Arrays.copyOfRange(encrypted_File_String.getBytes(), from, to);

			outputStream.write(original);

			System.out.println(Arrays.toString(outputStream.toByteArray()));

			System.out.println(" ************** ");

			System.out.println(Arrays.toString(Arrays.copyOfRange(encrypted_File_String.getBytes(), from, to)));

			for (i = 2; i <= quotient; i++) {
				from = to + 1;
				to = i * 1000;

				original = Arrays.copyOfRange(encrypted_File_String.getBytes(), from, to);

				outputStream.write(original);

				System.out.println(Arrays.toString(outputStream.toByteArray()));

				System.out.println(" ************** ");

				System.out.println(Arrays.toString(Arrays.copyOfRange(encrypted_File_String.getBytes(), from, to)));

			}

			original = Arrays.copyOfRange(encrypted_File_String.getBytes(), to + 1, to + reminder);

			outputStream.write(original);

			// System.out.println(Arrays.toString(Arrays.copyOfRange(encrypted_File_String.getBytes(),
			// 39001, 39000+79)));
			System.out.println(new String(outputStream.toByteArray()).equalsIgnoreCase(encrypted_File_String));

			// System.out.println(Arrays.toString(outputStream.toByteArray()));

			// System.out.println(" ************** ");

			// System.out.println(Arrays.toString(encrypted_File_String.getBytes()));

			new EncryptFile().decrypt(key, encryptedFile, decryptedFile);
		} catch (CryptoException ex) {
			System.out.println(ex.getMessage());
			ex.printStackTrace();
		}
	}

}

@SuppressWarnings("serial")
class CryptoException extends Exception {

	public CryptoException() {
	}

	public CryptoException(String message, Throwable throwable) {
		super(message, throwable);
	}
}
