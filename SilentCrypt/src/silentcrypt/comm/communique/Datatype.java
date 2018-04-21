package silentcrypt.comm.communique;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.exception.DecodingException;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

/**
 * Represents the specific type of data contained in a CommuniqueField.
 *
 * @author Andrew Binns
 * @author Michael Wells
 */
public class Datatype<T>
{
	private static final Map<Short, Datatype<?>>	reverse	= new HashMap<>();
	private static final Map<Class<?>, Datatype<?>>	types	= new HashMap<>();

	/**
	 * Represents purely binary data.
	 */
	public static final Datatype<byte[]> BINARY_BLOB = new Datatype<>(byte[].class, 0, ByteBuffer::wrap, U::toBytes);

	public static final Datatype<Byte>		BYTE	= new Datatype<>(Byte.class, 1, l -> ByteBuffer.allocate(Byte.BYTES).put(l), bb -> bb.get());
	public static final Datatype<Short>		SHORT	= new Datatype<>(Short.class, 2, l -> ByteBuffer.allocate(Short.BYTES).putShort(l), bb -> bb.getShort());
	public static final Datatype<Integer>	INTEGER	= new Datatype<>(Integer.class, 3, l -> ByteBuffer.allocate(Integer.BYTES).putInt(l), bb -> bb.getInt());
	public static final Datatype<Long>		LONG	= new Datatype<>(Long.class, 4, l -> ByteBuffer.allocate(Long.BYTES).putLong(l), bb -> bb.getLong());
	public static final Datatype<Float>		FLOAT	= new Datatype<>(Float.class, 5, l -> ByteBuffer.allocate(Float.BYTES).putDouble(l), bb -> bb.getFloat());
	public static final Datatype<Double>	DOUBLE	= new Datatype<>(Long.class, 6, l -> ByteBuffer.allocate(Long.BYTES).putDouble(l), bb -> bb.getDouble());

	/**
	 * Represents a String.
	 */
	public static final Datatype<String> STRING = new Datatype<>(String.class, 7, U::toBuff, U::toString);

	/**
	 * Represents a moment in time.
	 */
	public static final Datatype<Instant> INSTANT = new Datatype<>(Instant.class, 8, U::toBuff, U::toInstant);

	/**
	 * Represents a RSA key.
	 */
	public static final Datatype<RSAKeyParameters> RsaKey = new Datatype<>(RSAKeyParameters.class, 9, kp -> ByteBuffer.wrap(RsaUtil.toBytes(kp)), b -> RsaUtil.fromBytes(U.toBytes(b)));

	/**
	 * Represents an AES key.
	 */
	public static final Datatype<byte[]> AesKey = new Datatype<>(byte[].class, 10, ByteBuffer::wrap, U::toBytes);

	public static Datatype<?> get(short id)
	{
		Datatype<?> res = Datatype.reverse.get(id);
		if (res == null)
		{
			U.e("Error, unknown datatype " + id + "  defaulting to Binary Blob");
			return BINARY_BLOB;
		}
		return res;
	}

	public static <V> Datatype<? extends V> get(V data)
	{
		return U.quietCast(types.get(data.getClass()));
	}

	public static <V> Datatype<V> get(Class<V> clazz)
	{
		return U.quietCast(types.get(clazz));
	}

	/**
	 * @param id
	 * @return true if the given id is known by this version of the class.
	 */
	public static boolean isKnown(short id)
	{
		return Datatype.reverse.containsKey(id);
	}

	private short					id;
	private Class<T>				clazz;
	private Function<T, ByteBuffer>	encoder;
	private Function<ByteBuffer, T>	decoder;

	private Datatype(Class<T> datatype, int id, Function<T, ByteBuffer> encode, Function<ByteBuffer, T> decode)
	{
		this.id = (short) id;
		this.clazz = datatype;
		this.encoder = encode;
		this.decoder = decode;

		reverse.put(this.id, this);
		types.put(datatype, this);
	}

	/**
	 * @return the encoding id for this Datatype. Used when serializing fields.
	 */
	public short getId()
	{
		return this.id;
	}

	public Class<T> getDataClass()
	{
		return this.clazz;
	}

	public ByteBuffer encode(T data)
	{
		return this.encoder.apply(data);
	}

	public Object decode(ByteBuffer value) throws DecodingException
	{
		return this.decoder.apply(value);
	}

	public <V> V get(Class<V> clazz, ByteBuffer value) throws DecodingException
	{
		try
		{
			if (clazz.isAssignableFrom(this.clazz))
				return U.quietCast(this.decode(value));
			throw new DecodingException("Invalid type extracted from field.");
		} catch (IllegalArgumentException ex)
		{
			throw new DecodingException("Invalid data in field.", ex);
		}
	}
}