package silentcrypt.comm.communique;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

import silentcrypt.comm.exception.DecodingException;
import silentcrypt.comm.exception.EncodingException;
import silentcrypt.util.AesUtil;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

/**
 * @author Andrew Binns
 * @author Michael Wells
 */
public enum Encoding
{
	Uncompressed(0, b -> b, b -> b),
	Deflate(1, b -> b, b -> b),
	RsaEncrypt(2, (b, ms) -> RsaUtil.encrypt(b, ms.get(MetaSpace.RSA_EXTERN)), (b, ms) -> RsaUtil.decrypt(b, ms.get(MetaSpace.RSA_SELF).getPrivateRsa())),
	RsaSign(3, (b, ms) -> RsaUtil.encrypt(b, ms.get(MetaSpace.RSA_SELF).getPrivateRsa()), (b, ms) -> RsaUtil.decrypt(b, ms.get(MetaSpace.RSA_EXTERN))),
	Aes(4, (b, ms) -> AesUtil.encrypt(b, ms.get(MetaSpace.AES_KEY)), (b, ms) -> AesUtil.decrypt(b, ms.get(MetaSpace.AES_KEY)));

	private static BiFunction<ByteBuffer, MetaSpace, ByteBuffer> wrap(Func t)
	{
		return (ms, buff) -> {
			try
			{
				return t.apply(ms, buff);
			} catch (Exception e)
			{
				throw new IllegalArgumentException(e);
			}
		};
	}

	private interface Func
	{
		ByteBuffer apply(ByteBuffer b, MetaSpace ms) throws Exception;
	}

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

	private short											id;
	private BiFunction<ByteBuffer, MetaSpace, ByteBuffer>	encode;
	private BiFunction<ByteBuffer, MetaSpace, ByteBuffer>	decode;

	private Encoding(int id, Function<ByteBuffer, ByteBuffer> encode, Function<ByteBuffer, ByteBuffer> decode)
	{
		this.id = (short) id;
		this.encode = (buf, ms) -> encode.apply(buf);
		this.decode = (buf, ms) -> decode.apply(buf);
	}

	private Encoding(int id, Func encode, Func decode)
	{
		this.id = (short) id;
		this.encode = wrap(encode);
		this.decode = wrap(decode);
	}

	public ByteBuffer decode(ByteBuffer input, MetaSpace ms) throws DecodingException
	{
		try
		{
			return this.decode.apply(input, ms);
		} catch (IllegalArgumentException ex)
		{
			throw new DecodingException("Error decoding " + name() + " from field.", ex.getCause());
		}
	}

	public ByteBuffer encode(ByteBuffer input, MetaSpace ms) throws EncodingException
	{
		try
		{
			return this.encode.apply(input, ms);
		} catch (IllegalArgumentException ex)
		{
			throw new EncodingException("Error encoding " + name() + " to field.", ex.getCause());
		}
	}

	public short getId()
	{
		return this.id;
	}
}