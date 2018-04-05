package silentcrypt.util;

import java.nio.ByteBuffer;

import org.bouncycastle.util.Arrays;

/**
 * Contains some abstract binary data which can be encoded to and from byte buffers, byte arrays or Strings representing
 * either a normal string or base64 binary data.
 *
 * @author Michael
 */
public class BinaryData
{
	public static BinaryData fromString(String data)
	{
		return new BinaryData(U.toBytes(data));
	}

	public static BinaryData fromBase64(String data)
	{
		return new BinaryData(U.fromBase64(data));
	}

	public static BinaryData fromBuffer(ByteBuffer buffer)
	{
		byte[] data = new byte[buffer.remaining()];
		buffer.get(data);
		return new BinaryData(data);
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

	public ByteBuffer getBuffer()
	{
		return this.data.asReadOnlyBuffer();
	}

	public byte[] getBytes()
	{
		return Arrays.clone(this.data.array());
	}

	public int size()
	{
		return this.data.remaining();
	}

	public String toBase64()
	{
		return U.toBase64(this.data.array());
	}

	@Override
	public String toString()
	{
		return U.toString(this.data);
	}
}
