package silentcrypt.core.util;

import java.util.Arrays;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class AesUtil
{
	private static final AesUtil cipher = new AesUtil();

	private final PaddedBufferedBlockCipher	aesCipher	= new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
	private KeyParameter					key			= null;

	public void setKey(byte[] key)
	{
		// Ensure 256 bit key.
		if (key.length != 32)
			key = Arrays.copyOf(key, 32);

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
		this.aesCipher.init(encrypt, this.key);

		byte[] output = new byte[this.aesCipher.getOutputSize(input.length)];
		int bytesWrittenOut = this.aesCipher.processBytes(input, 0, input.length, output, 0);

		this.aesCipher.doFinal(output, bytesWrittenOut);

		return output;
	}

	public static BinaryData encrypt(BinaryData key, BinaryData input) throws InvalidCipherTextException
	{
		cipher.setKey(key.getBytes());
		return BinaryData.fromBytes(cipher.encrypt(input.getBytes()));
	}

	public static BinaryData decrypt(BinaryData key, BinaryData input) throws InvalidCipherTextException
	{
		cipher.setKey(key.getBytes());
		return BinaryData.fromBytes(cipher.decrypt(input.getBytes()));
	}
}