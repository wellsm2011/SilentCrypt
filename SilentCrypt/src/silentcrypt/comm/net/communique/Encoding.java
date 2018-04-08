package silentcrypt.comm.net.communique;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import silentcrypt.util.U;

/**
 * @author Andrew Binns
 * @author Michael Wells
 */
public enum Encoding
{
	Uncompressed(0, b -> b, b -> b),
	Deflate(1, b -> b, b -> b);

	private static final Map<Short, Encoding> reverse;

	static
	{
		reverse = Collections.unmodifiableMap(Arrays.stream(Encoding.values()).collect(Collectors.toMap(d -> d.id, d -> d)));
	}

	public static Encoding get(short id)
	{
		Encoding enc = Encoding.reverse.get(id);
		if (enc == null)
		{
			U.e("Error, unknown encoding " + id + " defaulting to uncompressed.");
			return Uncompressed;
		}
		return enc;
	}

	public static Encoding getDefault()
	{
		return Uncompressed;
	}

	public static boolean isKnown(short id)
	{
		return Encoding.reverse.containsKey(id);
	}

	private short								id;
	private Function<ByteBuffer, ByteBuffer>	encode;

	private Function<ByteBuffer, ByteBuffer> decode;

	private Encoding(int id, Function<ByteBuffer, ByteBuffer> encode, Function<ByteBuffer, ByteBuffer> decode)
	{
		this.id = (short) id;
		this.encode = encode;
		this.decode = decode;
	}

	public ByteBuffer decode(ByteBuffer input)
	{
		return this.decode.apply(input);
	}

	public ByteBuffer encode(ByteBuffer input)
	{
		return this.encode.apply(input);
	}

	public short getId()
	{
		return this.id;
	}
}