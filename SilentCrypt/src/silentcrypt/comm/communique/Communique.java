package silentcrypt.comm.communique;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.zip.CRC32;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.exception.DecodingException;
import silentcrypt.comm.exception.EncodingException;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

/**
 * <p>
 * Represents an abstract message which can be sent to or received from other systems or processes via any InputStream
 * or OutputStream.
 * </p>
 * <p>
 * Overall Structure
 * <ul>
 * <li>Header Data
 * <ul>
 * <li>Version Data</li>
 * <li>Timestamp -> long + int => Instant</li>
 * <li>Timestamp -> long + int => Instant</li>
 * <li>Flags - integer</li>
 * <li>Field Count - integer</li>
 * </ul>
 * </li>
 * <li>Optional Signed CRC
 * <ul>
 * <li>Integer Size of Signature</li>
 * <li>Signature Data</li>
 * </ul>
 * </li>
 * <li>Field List
 * <ul>
 * <li>DataType ID - Short</li>
 * <li>Encoding ID - Short</li>
 * <li>Data Size - Integer</li>
 * </ul>
 * </li>
 * <li>Field Data</li>
 * </ul>
 * </p>
 *
 * @author Andrew Binns
 * @author Michael Wells
 */
public class Communique
{
	private static enum Flag
	{
		/**
		 * If set, little endian, if unset, assumed to be big endian.
		 */
		Endieness(0),
		Signed(1);

		private int offset;

		Flag(int offset)
		{
			this.offset = offset;
		}
	}

	public static final byte[] V_0_3 = U.toBytes("AERIS-COMM-0004");

	/**
	 * @param in
	 * @return a supplier of new Communiques which are created by reading the given input stream.
	 */
	public static Supplier<Communique> from(InputStream in)
	{
		DataInputStream input = new DataInputStream(new BufferedInputStream(in, 65536));
		byte[] ver = Communique.getCurrentVersion();
		int headLen = Communique.getMinHeaderSize();
		return () -> {
			byte[] data;
			main: while (true)
				try
				{
					// Wait until we've gotten the version data
					for (byte b : ver)
					{
						int cur = input.read();
						// Bad data; abort!
						if (cur == -1)
							return null;
						// Potentially offset from a real message; keep looking.
						if (cur != b)
							continue main;
					}
					// Wait until we've gotten the rest of the header.
					while (input.available() < headLen - ver.length)
						U.sleep(5);

					// read the rest of the header, since we've already read the version
					data = new byte[headLen];
					int expectedRemainder = headLen - ver.length;
					if (input.read(data, ver.length, expectedRemainder) != expectedRemainder)
						continue;
					// backfill the version data that we already verified.
					for (int i = 0; i < ver.length; i++)
						data[i] = ver[i];

					/*
					 * Since we think we've gotten the beginnings of a communication, start parsing
					 */
					Communique c = new Communique();
					c.readOnly = true;
					try
					{
						c.parseHeaderData(ByteBuffer.wrap(data));
						if (c.flag(Flag.Signed))
						{
							c.sig = new byte[input.readShort()];
							input.read(c.sig);
						}
					} catch (DecodingException e)
					{
						U.e("Got malformed communique while parsing header: " + e.getMessage());
						continue;
					}

					List<CommuniqueField> fields = new ArrayList<>(c.fieldCount);
					Deque<Integer> fieldSizes = new ArrayDeque<>(c.fieldCount);
					for (int i = 0; i < c.fieldCount; i++)
					{
						short type = input.readShort();
						short encoding = input.readShort();
						fieldSizes.add(input.readInt());
						fields.add(new CommuniqueField(c.metaSpace, i, type, encoding));
					}

					for (CommuniqueField f : fields)
					{
						data = new byte[fieldSizes.pollFirst()];
						input.read(data);
						f.setData(ByteBuffer.wrap(data));
					}

					c.fields = fields;
					return c;
				} catch (SocketException e)
				{
					return null;
				} catch (IOException e)
				{
					U.e("Error reading from stream.", e);
					return null;
				}
		};
	}

	public MetaSpace getMetaSpace()
	{
		return this.metaSpace;
	}

	public Communique setMetaSpace(MetaSpace ms)
	{
		this.metaSpace = ms;
		this.fields.forEach(f -> f.setMetaSpace(ms));
		return this;
	}

	/**
	 * @return the current version of the Communique.
	 */
	public static byte[] getCurrentVersion()
	{
		return Arrays.copyOf(Communique.V_0_3, Communique.V_0_3.length);
	}

	/**
	 * @return the minimum size of a field with no data in it.
	 */
	private static int getMinFieldDefSize()
	{
		int res = 0;
		// Primitive datatype
		res += Short.BYTES;
		// Encoding method
		res += Short.BYTES;
		// Encoded data length
		res += Integer.BYTES;

		return res;
	}

	/**
	 * @return the minimum header size.
	 */
	private static int getMinHeaderSize()
	{
		int res = 0;
		// Version info
		res += Communique.getCurrentVersion().length;
		// Seconds since epoch (8 bytes)
		res += Long.BYTES;
		// Nanoseconds in second
		res += Integer.BYTES;
		// Seconds since epoch (8 bytes)
		res += Long.BYTES;
		// Nanoseconds in second
		res += Integer.BYTES;
		// flags
		res += Integer.BYTES;
		// field count
		res += Integer.BYTES;
		return res;
	}

	/**
	 * @param data
	 * @return a new Communique with one field for each of the provided data arrays
	 */
	public static Communique of(byte[]... data)
	{
		Communique ret = new Communique();
		for (byte[] d : data)
			ret.add(d);
		return ret;
	}

	/**
	 * @param s
	 * @return a new Communique with one field for each of the the provided strings
	 */
	public static Communique of(String... strings)
	{
		Communique ret = new Communique();
		for (String s : strings)
			ret.add(s);
		return ret;
	}

	private byte[]				version			= Communique.getCurrentVersion();
	private byte[]				sig				= new byte[0];
	private int					flags;
	private long				connectionId	= 0L;
	private transient MetaSpace	metaSpace		= new MetaSpace();

	private int fieldCount;

	private List<CommuniqueField> fields;

	private boolean readOnly = false;

	private Instant	sentTime;
	private Instant	signingTime	= Instant.now();

	/**
	 * Creates an empty Communique with zero fields.
	 */
	public Communique()
	{
		this.fields = new ArrayList<>();
	}

	/**
	 * Creates a read only Communique which reads the given buffer to populate its fields.
	 *
	 * @param data
	 * @throws DecodingException
	 */
	public Communique(ByteBuffer data) throws DecodingException
	{
		this.readOnly = true;
		parseHeaderData(data);
		if (flag(Flag.Signed))
		{
			this.sig = new byte[data.getShort()];
			data.get(this.sig);
		}

		ensureValidCapacityForFields(data);

		this.fields = extractFields(data);
	}

	/**
	 * Sets this Communique's connection ID.
	 *
	 * @param id
	 * @return
	 */
	public Communique setConnectionId(long id)
	{
		if (!this.readOnly)
			throw new IllegalStateException("Connection ID can't be set for sending messages.");
		if (this.connectionId != 0L)
			throw new IllegalStateException("Connection ID already set.");
		if (id < 1)
			throw new IllegalStateException("Connection ID must be positive.");
		this.connectionId = id;
		return this;
	}

	/**
	 * @return the connection ID representing the source of this Communique.
	 */
	public long getConnectionId()
	{
		return this.connectionId;
	}

	/**
	 * Copies the given CommuniqueField into the next slot of this message.
	 *
	 * @param field
	 * @return
	 */
	public Communique add(CommuniqueField field)
	{
		if (this.readOnly)
			throw new EncodingException("Please do not modify an existing communique.");
		this.sig = new byte[0];
		this.fieldCount++;
		this.fields.add(new CommuniqueField(this.metaSpace, this.fields.size(), field.getDatatype().getId(), field.getDatatype().getId(), field.encodedData()));
		return this;
	}

	public <T> Communique add(T data) throws IllegalArgumentException
	{
		this.add(Encoding.getDefault(), data);
		return this;
	}

	public <T> Communique add(Encoding encoding, T data) throws IllegalArgumentException
	{
		this.add(Datatype.get(data), encoding, data);
		return this;
	}

	public <T> Communique add(Datatype<T> datatype, Encoding encoding, T data)
	{
		Objects.requireNonNull(datatype, "Invalid data type provided.");
		Objects.requireNonNull(encoding);

		if (this.readOnly)
			throw new EncodingException("Please do not modify an existing communique.");
		this.sig = new byte[0];
		this.fieldCount++;
		this.fields.add(new CommuniqueField(this.metaSpace, this.fields.size(), datatype.getId(), encoding.getId(), datatype.encode(data)));
		return this;
	}

	/**
	 * Verifies that this Communique has the proper information in it's Metaspace to encode or decode the message.
	 *
	 * @throws EncodingException
	 * @throws DecodingException
	 */
	public Communique ensureFields() throws EncodingException, DecodingException
	{
		for (CommuniqueField f : this.fields)
		{
			f.ensureData();
			f.ensureEncodedData();
		}
		return this;
	}

	/**
	 * Attempts to extract this Communique into the specified class. The given class must be instancable with a no-args
	 * constructor.
	 *
	 * @param clazz
	 * @return
	 */
	public <T> T extractTo(Class<T> datatype)
	{
		if (!canExtractTo(datatype))
			return null;

		try
		{
			Class<?> clazz = datatype;
			T instance = datatype.getConstructor().newInstance();

			for (; clazz != null; clazz = clazz.getSuperclass())
			{
				Field[] fields = clazz.getFields();
				for (int i = 0; i < fields.length; ++i)
				{
				}
			}

			return instance;
		} catch (IllegalArgumentException | ReflectiveOperationException | SecurityException e)
		{
			return null;
		}
	}

	/**
	 * Returns true if the fields of this Communique match the fields in the given class
	 *
	 * @param clazz
	 * @return
	 */
	public boolean canExtractTo(Class<?> clazz)
	{
		if (!hasSameFieldLength(clazz))
			return false;

		try
		{
			clazz.getConstructor();

			for (; clazz != null; clazz = clazz.getSuperclass())
			{
				Field[] fields = clazz.getFields();
				for (int i = 0; i < fields.length; ++i)
				{
					// We don't encode static or transient fields.
					if (Modifier.isStatic(fields[i].getModifiers()) || Modifier.isTransient(fields[i].getModifiers()))
						continue;

					Datatype<?> fieldType = Datatype.get(fields[i].getType());
					if (!Objects.equals(this.fields.get(i).getDatatype(), (fieldType)))
						return false;
				}
			}
			return true;
		} catch (NoSuchMethodException | SecurityException e)
		{
			return false;
		}
	}

	private boolean hasSameFieldLength(Class<?> clazz)
	{
		long classFieldCount = 0;
		for (; clazz != null; clazz = clazz.getSuperclass())
			classFieldCount += Arrays.stream(clazz.getDeclaredFields()).filter(f -> !Modifier.isStatic(f.getModifiers()) && !Modifier.isTransient(f.getModifiers())).count();

		return classFieldCount == this.fieldCount;
	}

	private byte[] checksum()
	{
		CRC32 algorithm = new CRC32();

		// A checksum for all fields plus a timestamp.
		ByteBuffer checksum = ByteBuffer.allocate(Long.BYTES + Long.BYTES + Integer.BYTES);
		for (CommuniqueField field : this.fields)
			algorithm.update(field.encodedData());
		checksum.putLong(algorithm.getValue());
		checksum.putLong(this.signingTime.getEpochSecond());
		checksum.putInt(this.signingTime.getNano());
		return checksum.array();
	}

	/**
	 * @param key
	 * @return this object
	 * @throws InvalidCipherTextException
	 */
	public Communique sign() throws IllegalStateException
	{
		try
		{
			RSAKeyParameters key = this.metaSpace.get(MetaSpace.RSA_SELF).getPrivateRsa();
			if (this.readOnly)
				throw new IllegalStateException("Cannot sign a read only message.");
			this.signingTime = Instant.now();
			this.sig = RsaUtil.encrypt(checksum(), key);
			return this;
		} catch (InvalidCipherTextException e)
		{
			throw new IllegalStateException("Could not sign Communique.", e);
		}
	}

	/**
	 * @return true iff this message has been signed using the {@link #sign(RSAKeyParameters)} method.
	 */
	public boolean isSigned()
	{
		return this.sig.length != 0;
	}

	/**
	 * @param key
	 * @return True iff this message was signed with the complementary RSA key and the enclosed checksum matches.
	 * @throws InvalidCipherTextException
	 */
	public boolean validate(RSAKeyParameters key)
	{
		if (!isSigned())
			return false;

		// Compare checksums.
		try
		{
			byte[] checksum = checksum();
			byte[] sig = RsaUtil.decrypt(this.sig, key);

			if (sig.length != checksum.length)
				return false;

			for (int i = 0; i < checksum.length; ++i)
			{
				if (sig[i] != checksum[i])
					return false;
			}
		} catch (InvalidCipherTextException ex)
		{
			return false;
		}

		return true;
	}

	/**
	 * @return a serialized verson of this Communique.
	 */
	public byte[] bytes()
	{
		return compile().array();
	}

	private void setFlag(Flag f)
	{
		this.flags |= 1 << f.offset;
	}

	private void clearFlag(Flag f)
	{
		this.flags &= ~(1 << f.offset);
	}

	private ByteBuffer compile()
	{
		int msgSize = 0;
		msgSize += Communique.getMinHeaderSize();
		msgSize += this.sig.length;
		msgSize += this.fieldCount * Communique.getMinFieldDefSize();
		msgSize += this.fields.stream().mapToInt(CommuniqueField::getEncodedSize).sum();
		ByteBuffer res = ByteBuffer.allocate(msgSize);
		// enable when DataInputStream actually supports endienness...
		// if (false)
		// if (res.order().equals(ByteOrder.BIG_ENDIAN))
		// clearFlag(Flag.Endieness);
		// else
		// setFlag(Flag.Endieness);
		res.order(ByteOrder.BIG_ENDIAN);
		clearFlag(Flag.Endieness);

		// header data
		res.put(Communique.getCurrentVersion());
		U.toBuff(this.signingTime, res);
		U.toBuff(Instant.now(), res);
		res.putInt(this.flags);
		res.putInt(this.fieldCount);
		if (flag(Flag.Signed))
		{
			res.putInt(this.sig.length);
			res.put(this.sig);
		}

		// field data
		this.fields.forEach(f -> f.compile(res));

		this.fields.forEach(f -> {
			f.encodedData().rewind();
			res.put(f.encodedData());
		});

		return res;
	}

	/**
	 * @param index
	 * @return the binary data of the field at the given index.
	 */
	public byte[] data(int index)
	{
		ByteBuffer b = this.fields.get(index).encodedData();
		byte[] res = new byte[b.capacity()];
		b.rewind();
		b.get(res);
		return res;
	}

	private void ensureValidCapacityForFields(ByteBuffer data) throws DecodingException
	{
		if (data.remaining() < Communique.getMinFieldDefSize() * this.fieldCount)
			throw new DecodingException("Insufficient data, field declaration too small.");
		// Mark end of static header and beginning of non-static pieces
		data.mark();
		int minRemaining = 0;
		for (int i = 0; i < this.fieldCount; i++)
		{
			// skip type data during this first sizing check
			// Datatype
			data.getShort();
			// Encoding
			data.getShort();
			int t = data.getInt();
			if (t < 0)
				throw new DecodingException("Negative field size, this probably means we have a encoding error.");
			minRemaining += t;
		}
		if (minRemaining > data.remaining())
			throw new DecodingException("Malformed data, not enough remaining in buffer.");
		data.reset();
	}

	private List<CommuniqueField> extractFields(ByteBuffer data)
	{
		int dataStart = data.position() + this.fieldCount * Communique.getMinFieldDefSize();
		List<CommuniqueField> res = new ArrayList<>();
		for (int i = 0; i < this.fieldCount; i++)
		{
			short type = data.getShort();
			short encoding = data.getShort();
			int size = data.getInt();
			data.mark();
			data.position(dataStart);
			ByteBuffer curData = ((ByteBuffer) data.duplicate().limit(size)).slice();
			dataStart += size;
			data.reset();
			res.add(new CommuniqueField(this.metaSpace, i, type, encoding, curData));
		}
		return res;
	}

	/**
	 * @return the number of fields in this Communique.
	 */
	public int fieldCount()
	{
		return this.fieldCount;
	}

	private boolean flag(Flag flag)
	{
		return (this.flags & 1 << flag.offset) > 0;
	}

	/**
	 * @return the time this object was most recently signed. For Communiques that are received by the system, this
	 *         value is the reported creation time by the external system. If the Communique is signed,
	 *         {@link #validate(RSAKeyParameters)} will verify that the timestamp was created by the sender. If it is
	 *         not signed, this time usually represents the time the remote system began to construct the message.
	 */
	public Instant getTimestamp()
	{
		return this.signingTime;
	}

	/**
	 * @return A list of all fields.
	 */
	public List<CommuniqueField> getFields()
	{
		return this.fields;
	}

	/**
	 * @param index
	 * @return the field at the given index.
	 * @throws IndexOutOfBoundsException
	 *             if the index is out of range (index < 0 || index >= {@link #fieldCount()})
	 */
	public CommuniqueField getField(int index) throws IndexOutOfBoundsException
	{
		return this.fields.get(index);
	}

	/**
	 * @return the reported <i>send</i> time of this Communique. This value cannot be verified for Communiques that are
	 *         received by the system, but will always be accurate for Communiques that the system sends.
	 */
	public Instant getSentTime()
	{
		return this.sentTime;
	}

	/**
	 * @return the number of bytes in the signature field
	 * @throws DecodingException
	 */
	private void parseHeaderData(ByteBuffer data) throws DecodingException
	{
		// Parse header data
		if (data.remaining() < Communique.getMinHeaderSize())
			throw new DecodingException(
					"Insufficient data; header too small for standard header. Expected at least " + Communique.getMinHeaderSize() + " bytes, but only got " + data.remaining() + ".");
		this.version = new byte[Communique.getCurrentVersion().length];
		data.get(this.version);
		this.signingTime = U.toInstant(data);
		this.sentTime = U.toInstant(data);
		// TODO add communique version checking
		data.order(ByteOrder.BIG_ENDIAN);
		this.flags = data.getInt();
		if (flag(Flag.Endieness))
			data.order(ByteOrder.LITTLE_ENDIAN);
		this.fieldCount = data.getInt();

		if (this.fieldCount < 0)
			throw new DecodingException("Invalid field count");
	}

	/**
	 * @param modifier
	 * @return this object
	 */
	public Communique processAll(Consumer<CommuniqueField> modifier)
	{
		this.fields.parallelStream().forEach(modifier);
		return this;
	}

	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder();

		sb.append("Communique ");
		sb.append("Version:").append(U.toString(this.version)).append(' ');
		sb.append("FieldCount:").append(this.fieldCount);

		for (Flag f : Flag.values())
			sb.append(' ').append(f.toString() + ":").append(flag(f));
		for (CommuniqueField f : this.fields)
		{
			sb.append(' ').append(f.getDatatype()).append(' ').append(f.getEncoding()).append('[').append(f.getEncodedSize()).append(']');
			if (f.getDatatype().equals(Datatype.STRING))
				sb.append(' ').append(U.toString(data(f.getFieldIndex())));
		}

		return sb.toString();
	}

	/**
	 * Serializes this Communique and pushes it out over the given OutputStream.
	 *
	 * @param out
	 * @throws IOException
	 */
	public void write(OutputStream out) throws IOException
	{
		ByteBuffer data = compile();
		out.write(data.array());
	}
}
