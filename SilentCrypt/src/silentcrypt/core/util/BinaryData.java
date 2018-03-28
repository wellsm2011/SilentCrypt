package silentcrypt.core.util;

import org.bouncycastle.util.Arrays;

public class BinaryData
{
	private byte[] data = null;

	private BinaryData(byte[] data)
	{
		this.data = data;
	}

	@Override
	public String toString()
	{
		return new String(this.data);
	}

	public String toBase64()
	{
		return U.toBase64(this.data);
	}

	public byte[] getBytes()
	{
		return Arrays.clone(this.data);
	}

	public static BinaryData fromBase64(String data)
	{
		return new BinaryData(U.fromBase64(data));
	}

	public static BinaryData fromString(String data)
	{
		return new BinaryData(U.toBytes(data));
	}

	public static BinaryData fromBytes(byte[] data)
	{
		return new BinaryData(data);
	}
}
