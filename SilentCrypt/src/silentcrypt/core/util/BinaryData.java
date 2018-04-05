package silentcrypt.core.util;

import java.nio.ByteBuffer;

import org.bouncycastle.util.Arrays;

public class BinaryData
{
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
		return new BinaryData(Arrays.clone(data));
	}

	private ByteBuffer data;

	private BinaryData(byte[] data)
	{
		this.data = ByteBuffer.wrap(data);
	}

	public int size()
	{
		return this.data.remaining();
	}

	public String toBase64()
	{
		return U.toBase64(this.data.array());
	}

	public byte[] getBytes()
	{
		return Arrays.clone(this.data.array());
	}

	public ByteBuffer getBuffer()
	{
		return this.data.asReadOnlyBuffer();
	}

	@Override
	public String toString()
	{
		return new String(this.data.array());
	}
}
