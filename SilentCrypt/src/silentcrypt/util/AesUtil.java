package silentcrypt.util;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Provides support for AES-256 encryption.
 *
 * @author Michael Wells
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
	public static byte[] decrypt(byte[] key, byte[] input) throws InvalidCipherTextException
	{
		return AesUtil.cipher.setKey(key).decrypt(input);
	}

	public static ByteBuffer decrypt(ByteBuffer key, byte[] input) throws InvalidCipherTextException
	{
		return ByteBuffer.wrap(decrypt(U.toBytes(key), input));
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
	public static byte[] encrypt(byte[] key, byte[] input) throws InvalidCipherTextException
	{
		return AesUtil.cipher.setKey(key).encrypt(input);
	}

	public static ByteBuffer encrypt(ByteBuffer key, byte[] input) throws InvalidCipherTextException
	{
		return ByteBuffer.wrap(encrypt(U.toBytes(key), input));
	}

	private final PaddedBufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

	private byte[]			outputBuffer	= new byte[2048];
	private KeyParameter	key				= null;

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

		int outputSize = this.aesCipher.getOutputSize(input.length);
		if (outputSize > this.outputBuffer.length)
			this.outputBuffer = new byte[outputSize * 2];

		int bytesWrittenOut = this.aesCipher.processBytes(input, 0, input.length, this.outputBuffer, 0);
		bytesWrittenOut += this.aesCipher.doFinal(this.outputBuffer, bytesWrittenOut);

		return Arrays.copyOf(this.outputBuffer, bytesWrittenOut);
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
		String secret = "Top Secret Message!";
		String key = "Secret Key";

		U.p("Secret: " + secret);
		U.p("Secret Bytes: " + U.niceToString(secret.getBytes()));
		U.p("Key: " + key);
		byte[] cipherText = encrypt(U.toBytes(key), U.toBytes(secret));
		U.p("Cipher Bytes: " + U.niceToString(cipherText));
		byte[] plainText = decrypt(U.toBytes(key), cipherText);
		U.p("Plaintext: " + U.toString(plainText));
		U.p("Plaintext Bytes: " + U.niceToString(plainText));
	}
}