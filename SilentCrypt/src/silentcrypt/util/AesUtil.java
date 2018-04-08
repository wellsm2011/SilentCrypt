package silentcrypt.util;

import java.util.Arrays;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Provides support for AES-256 encryption.
 *
 * @author Michael
 */
public class AesUtil
{
	/**
	 * Number of bytes in an AES key.
	 */
	public static final int AES_KEY_SIZE = 32;

	private static final AesUtil cipher = new AesUtil();

	/**
	 * Performs AES-256 decryption using the given key and input. Expects to see padded CBC blocks to mask the length of
	 * data.
	 *
	 * @param key
	 *            The key to decrypt with. It will be padded or truncated to ensure 256 bits.
	 * @param input
	 *            The binary data to decrypt.
	 * @return A BinaryData blob containing the decrypted data.
	 * @throws InvalidCipherTextException
	 */
	public static BinaryData decrypt(BinaryData key, BinaryData input) throws InvalidCipherTextException
	{
		return BinaryData.fromBytes(AesUtil.cipher.setKey(key.getBytes()).decrypt(input.getBytes()));
	}

	/**
	 * Performs AES-256 encryption using the given key and input. Performs encryption using padded CBC blocks to mask
	 * the length of data.
	 *
	 * @param key
	 *            The key to encrypt with. It will be padded or truncated to ensure 256 bits.
	 * @param input
	 *            The binary data to encrypt.
	 * @return A BinaryData blob containing the encrypted data.
	 * @throws InvalidCipherTextException
	 */
	public static BinaryData encrypt(BinaryData key, BinaryData input) throws InvalidCipherTextException
	{
		return BinaryData.fromBytes(AesUtil.cipher.setKey(key.getBytes()).encrypt(input.getBytes()));
	}

	private final PaddedBufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());

	private KeyParameter key = null;

	private AesUtil()
	{
	}

	public byte[] decrypt(byte[] input) throws DataLengthException, InvalidCipherTextException
	{
		return processing(input, false);
	}

	public byte[] encrypt(byte[] input) throws DataLengthException, InvalidCipherTextException
	{
		return processing(input, true);
	}

	private byte[] processing(byte[] input, boolean encrypt) throws DataLengthException, InvalidCipherTextException
	{
		this.aesCipher.init(encrypt, this.key);

		byte[] output = new byte[this.aesCipher.getOutputSize(input.length)];
		int bytesWrittenOut = this.aesCipher.processBytes(input, 0, input.length, output, 0);
		bytesWrittenOut += this.aesCipher.doFinal(output, bytesWrittenOut);

		if (bytesWrittenOut != output.length)
		{
			byte[] realOutput = new byte[bytesWrittenOut];
			for (int i = 0; i < realOutput.length; ++i)
				realOutput[i] = output[i];
			output = realOutput;
		}

		return output;
	}

	public AesUtil setKey(byte[] key)
	{
		// Ensure 256 bit key.
		if (key.length != AesUtil.AES_KEY_SIZE)
			key = Arrays.copyOf(key, AesUtil.AES_KEY_SIZE);

		this.key = new KeyParameter(key);
		return this;
	}

	public static void main(String... strings) throws InvalidCipherTextException
	{
		U.p("--- Starting AES Tests ---");
		BinaryData secret = BinaryData.fromString("Top Secret Message!!!!!!!!!");
		BinaryData key = BinaryData.fromString("Secret Key");

		U.p("Secret: " + secret);
		U.p("Secret Bytes: " + U.niceToString(secret.getBytes()));
		U.p("Key: " + key);
		BinaryData cipherText = encrypt(key, secret);
		U.p("Cipher Bytes: " + U.niceToString(cipherText.getBytes()));
		BinaryData plainText = decrypt(key, cipherText);
		U.p("Plaintext: " + plainText.toString());
		U.p("Plaintext Bytes: " + U.niceToString(plainText.getBytes()));
	}
}