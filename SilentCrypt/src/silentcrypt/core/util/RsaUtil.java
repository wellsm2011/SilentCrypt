package silentcrypt.core.util;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public class RsaUtil
{
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

	public static BinaryData encrypt(BinaryData data, RSAKeyParameters key)
	{
		Security.addProvider(new BouncyCastleProvider());

		RSAEngine engine = new RSAEngine();
		engine.init(true, key);

		byte[] cipherBytes = engine.processBlock(data.getBytes(), 0, data.getBytes().length);

		return BinaryData.fromBytes(cipherBytes);
	}

	public static BinaryData decrypt(BinaryData encrypted, RSAKeyParameters key) throws InvalidCipherTextException
	{
		Security.addProvider(new BouncyCastleProvider());

		AsymmetricBlockCipher engine = new RSAEngine();
		engine.init(false, key);

		byte[] encryptedBytes = encrypted.getBytes();
		byte[] hexEncodedCipher = engine.processBlock(encrypted.getBytes(), 0, encryptedBytes.length);

		return BinaryData.fromBytes(hexEncodedCipher);
	}

	public static RSAKeyParameters fromBytes(byte[] key)
	{
		if (key[0] > key.length - 2)
			throw new IllegalArgumentException("Invalid exponent length field.");

		byte[] exp = Arrays.copyOfRange(key, 1, key[0] + 1);
		byte[] mod = Arrays.copyOfRange(key, key[0] + 1, key.length);

		return new RSAKeyParameters(false, new BigInteger(mod), new BigInteger(exp));
	}

	public static byte[] toBytes(RSAKeyParameters key)
	{
		byte[] mod = key.getModulus().toByteArray();
		byte[] exp = key.getExponent().toByteArray();

		if (exp.length > Byte.MAX_VALUE)
			throw new IllegalArgumentException("Exponent length cannot fit in one byte; length: " + exp.length);

		byte[] keyBytes = new byte[mod.length + exp.length + 4];
		keyBytes[0] = (byte) exp.length;
		for (int i = 0; i < exp.length; ++i)
			keyBytes[i + 1] = exp[i];
		for (int i = 0; i < mod.length; ++i)
			keyBytes[i + 1 + exp.length] = mod[i];
		return keyBytes;
	}
}
