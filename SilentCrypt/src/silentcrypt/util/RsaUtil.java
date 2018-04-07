package silentcrypt.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Contains utility functions for working with RSA public key encryption.
 *
 * @author Michael
 */
public class RsaUtil
{
	// Magic number for encryption.
	private static final String RSA_VERSION = "SC-RSA-0001";

	/**
	 * Performs RSA decryption on the given data using the given key.
	 *
	 * @param data
	 *            The data to decrypt.
	 * @param key
	 *            The key to decrypt with.
	 * @return A binary blob containing the decrypted data.
	 * @throws InvalidCipherTextException
	 *             If the given RSA key is incorrect, or the encrypted data was not created by this class.
	 */
	public static BinaryData decrypt(BinaryData encrypted, RSAKeyParameters key) throws InvalidCipherTextException
	{
		ByteBuffer message = encrypted.getBuffer();
		int rsaBlockSize = message.getInt();
		byte[] rsaBlock = new byte[rsaBlockSize];
		message.get(rsaBlock);

		// Use RSA to obtain our AES key.
		Security.addProvider(new BouncyCastleProvider());
		AsymmetricBlockCipher engine = new RSAEngine();
		engine.init(false, key);
		byte[] aesKey = engine.processBlock(rsaBlock, 0, rsaBlock.length);
		byte[] aesCipher = new byte[message.remaining()];
		message.get(aesCipher);

		// Decrypt original message using AES and ensure we have the correct magic bytes signifying correct keys.
		ByteBuffer result = AesUtil.decrypt(BinaryData.fromBytes(aesKey), BinaryData.fromBytes(aesCipher)).getBuffer();
		byte[] expectedMagicNumber = U.toBytes(RSA_VERSION);
		byte[] magicNumber = new byte[expectedMagicNumber.length];
		result.get(magicNumber);
		for (int i = 0; i < magicNumber.length; ++i)
			if (magicNumber[i] != expectedMagicNumber[i])
				throw new InvalidCipherTextException("Wrong RSA key or data was not encrypted with this version of SilentCrypt.");

		byte[] ret = new byte[result.remaining()];
		result.get(ret);
		return BinaryData.fromBytes(ret);
	}

	/**
	 * Performs RSA encryption on the given data using the given key. Can be reversed by calling
	 * {@link #decrypt(BinaryData, RSAKeyParameters)} with the complimentary RSA key.
	 *
	 * @param data
	 *            The data to encrypt.
	 * @param key
	 *            The key to encrypt with.
	 * @return A binary blob containing the encrypted data.
	 * @throws InvalidCipherTextException
	 */
	public static BinaryData encrypt(BinaryData data, RSAKeyParameters key) throws InvalidCipherTextException
	{
		// End result will be [[key length][rsa-encrypted aes key][aes encrypted data]]

		// Generate AES key at random.
		byte[] aesKey = new byte[AesUtil.AES_KEY_SIZE];
		new Random().nextBytes(aesKey);

		Security.addProvider(new BouncyCastleProvider());
		RSAEngine engine = new RSAEngine();
		engine.init(true, key);

		byte[] rsaCipher = engine.processBlock(aesKey, 0, aesKey.length);
		byte[] magicNumber = U.toBytes(RSA_VERSION);
		ByteBuffer aesPlainText = ByteBuffer.allocate(data.size() + magicNumber.length);
		aesPlainText.put(magicNumber);
		aesPlainText.put(data.getBuffer());
		BinaryData aesCipher = AesUtil.encrypt(BinaryData.fromBytes(aesKey), BinaryData.fromBytes(aesPlainText.array()));

		ByteBuffer message = ByteBuffer.allocate(rsaCipher.length + aesCipher.size() + Integer.BYTES);
		message.putInt(rsaCipher.length);
		message.put(rsaCipher);
		message.put(aesCipher.getBuffer());

		return BinaryData.fromBytes(message.array());
	}

	/**
	 * Encodes a key from a given byte array. This operation can be reversed with {@link #toBytes(RSAKeyParameters)}.
	 *
	 * @param key
	 *            A byte array containing the components of the key.
	 * @return The RSA key contained in the byte array.
	 */
	public static RSAKeyParameters fromBytes(byte[] key)
	{
		byte[] expectedMagicNumber = U.toBytes(RSA_VERSION);
		if (key.length < Integer.BYTES * 2 + expectedMagicNumber.length)
			throw new IllegalArgumentException("Invalid encoded RSA data format: not enough data to extract key");

		ByteBuffer wrapped = ByteBuffer.wrap(key);
		byte[] magicNumber = new byte[expectedMagicNumber.length];
		wrapped.get(magicNumber);
		for (int i = 0; i < magicNumber.length; ++i)
			if (magicNumber[i] != expectedMagicNumber[i])
				throw new IllegalArgumentException("RSA data was not encoded with this version of SilentCrypt.");

		int expLen = wrapped.getInt();
		int modLen = wrapped.getInt();

		if (expLen < 1)
			throw new IllegalArgumentException("Invalid encoded RSA data format: exponent length is negative (" + expLen + ")");
		if (modLen < 1)
			throw new IllegalArgumentException("Invalid encoded RSA data format: modulus length is negative (" + modLen + ")");

		long expectedCapacity = expLen + (long) modLen;
		if (wrapped.remaining() != expectedCapacity)
			throw new IllegalArgumentException("Invalid encoded RSA data format: bad data length (decoded: " + expectedCapacity + ", actual: " + wrapped.capacity() + ")");

		byte[] exp = new byte[expLen];
		byte[] mod = new byte[modLen];

		wrapped.get(exp).get(mod);

		return new RSAKeyParameters(false, new BigInteger(mod), new BigInteger(exp));
	}

	/**
	 * Encodes a given key to a byte array. This operation can be reversed with {@link #fromBytes(byte[])}.
	 *
	 * @param key
	 *            The RSA key to encode.
	 * @return A byte array containing the components of the key.
	 */
	public static byte[] toBytes(RSAKeyParameters key)
	{
		byte[] exp = key.getExponent().toByteArray();
		byte[] mod = key.getModulus().toByteArray();

		// Format: [[exp length][mod length][exp][mod]]

		byte[] magicNumber = U.toBytes(RSA_VERSION);
		ByteBuffer res = ByteBuffer.allocate(Integer.BYTES * 2 + exp.length + mod.length + magicNumber.length);
		res.put(magicNumber);
		res.putInt(exp.length);
		res.putInt(mod.length);
		res.put(exp);
		res.put(mod);
		return res.array();
	}

	/**
	 * Generates a brand new RSA key pair.
	 * <p>
	 * <b>WARNING</b>: This is a computationally expensive operation.
	 *
	 * @return
	 */
	public static RsaKeyPair generateKeyPair()
	{
		RSAKeyPairGenerator generator = new RSAKeyPairGenerator();

		try
		{
			generator.init(new RSAKeyGenerationParameters(new BigInteger("10001", 16), SecureRandom.getInstance("SHA1PRNG"), 4096, 80));
		} catch (NoSuchAlgorithmException e)
		{
			// Big problems if we get here.
			throw new UnsupportedOperationException(e);
		}

		AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
		return new RsaKeyPair(U.quietCast(keyPair.getPublic()), U.quietCast(keyPair.getPrivate()));
	}

	public static void main(String... strings) throws InvalidCipherTextException
	{
		U.p("--- Starting RSA Utility Tests ---");

		String secret = "Top Secret Message!";
		U.p("Generating a new RSA key...");
		RsaKeyPair key = RsaUtil.generateKeyPair();
		U.p("Public key: " + U.toString(key.getPublicRsa()));
		U.p("Private key: " + U.toString(key.getPrivateRsa()));

		byte[] publicBytes = toBytes(key.getPublicRsa());
		U.p("Encoded public key: " + U.niceToString(publicBytes));
		U.p("Decoded public key: " + U.toString(fromBytes(publicBytes)));

		BinaryData encrypted = encrypt(BinaryData.fromString(secret), key.getPrivateRsa());
		U.p("Original message: " + secret);
		U.p("Encrypted message: " + U.niceToString(encrypted.getBytes()));
		U.p("Decrypted message: " + decrypt(encrypted, key.getPublicRsa()));
	}
}
