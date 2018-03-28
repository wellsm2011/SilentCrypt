package silentcrypt.core.util;

import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class UtilTestDriver
{
	public static void main(String... cheese) throws InvalidCipherTextException
	{
		BinaryData plainMessage = BinaryData.fromString("Top Secret Message");
		BinaryData key = BinaryData.fromString("taco");

		U.p("Original Text: " + plainMessage);
		U.p("AES Key: " + key);
		U.p("AES Key Bytes: " + Arrays.toString(key.getBytes()));

		BinaryData cipher = AesUtil.encrypt(key, plainMessage);
		U.p("AES Cipher Text: " + cipher.toBase64());
		BinaryData orig = AesUtil.decrypt(key, cipher);
		U.p("Decrypted AES Text: " + orig);

		// AsymmetricCipherKeypair includes both private and public keys, but AsymmetricKeyPair includes only public
		RsaKeyPair keyPair = RsaUtil.generateKeyPair();
		U.p("RSA Key Pair: " + toString(keyPair));

		BinaryData encryptedMessage = RsaUtil.encrypt(plainMessage, keyPair.getPublic());
		U.p("RSA Cipher Text: " + encryptedMessage.toBase64());

		BinaryData decryptedMessage = RsaUtil.decrypt(encryptedMessage, keyPair.getPrivate());
		U.p("Decrypted RSA Text: " + decryptedMessage);
	}

	private static String toString(RsaKeyPair key)
	{
		return "[publicKey=" + toString(key.getPublic()) + ", private=" + toString(key.getPrivate()) + "]";
	}

	private static String toString(RSAKeyParameters params)
	{
		return "[exp=" + params.getExponent() + ", mod=" + params.getModulus() + "]";
	}
}
