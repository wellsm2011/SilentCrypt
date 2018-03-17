package silentcrypt.core.util;

import java.util.Base64;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class AesUtil
{
	private static final AesUtil cipher = new AesUtil();
	private final BlockCipher AESCipher = new AESEngine();

	private PaddedBufferedBlockCipher	pbbc;
	private KeyParameter				key;

	public void setPadding(BlockCipherPadding bcp)
	{
		this.pbbc = new PaddedBufferedBlockCipher(AESCipher, bcp);
	}

	public void setKey(byte[] key)
	{
		this.key = new KeyParameter(key);
	}

	public byte[] encrypt(byte[] input) throws DataLengthException, InvalidCipherTextException
	{
		return processing(input, true);
	}

	public byte[] decrypt(byte[] input) throws DataLengthException, InvalidCipherTextException
	{
		return processing(input, false);
	}

	private byte[] processing(byte[] input, boolean encrypt) throws DataLengthException, InvalidCipherTextException
	{

		pbbc.init(encrypt, key);

		byte[] output = new byte[pbbc.getOutputSize(input.length)];
		int bytesWrittenOut = pbbc.processBytes(input, 0, input.length, output, 0);

		pbbc.doFinal(output, bytesWrittenOut);

		return output;

	}

	public static byte[] encrypt(byte[] key, byte[] input) throws InvalidCipherTextException {
		cipher.setKey(key);
		return cipher.encrypt(input);
	}
	
	public static byte[] decrypt(byte[] key, byte[] input) throws InvalidCipherTextException {
		cipher.setKey(key);
		return cipher.decrypt(input);
	}
	
	public static String encrypt(byte[] key, String input) throws InvalidCipherTextException {
		return toBase64(encrypt(key, input.getBytes()));
	}
	
	public static String decrypt(byte[] key, String input) throws InvalidCipherTextException {
		return new String(decrypt(key, fromBase64(input)));
	}

	private static String toBase64(byte[] input) {
		return new String(Base64.getEncoder().encode(input));
	}
	
	private static byte[] fromBase64(String input) {
		return Base64.getDecoder().decode(input);
	}
}