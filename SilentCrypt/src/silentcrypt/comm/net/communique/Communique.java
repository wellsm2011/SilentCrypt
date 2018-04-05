package silentcrypt.comm.net.communique;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import silentcrypt.comm.net.exception.DecodingException;
import silentcrypt.comm.net.exception.EncodingException;
import silentcrypt.util.U;

/**
 * Represents an abstract message which can be sent to or received from other systems or processes via any InputStream
 * or OutputStream.
 *
 * @author Andrew
 * @author Michael
 */
public class Communique
{
	private static enum Flag
	{
		/**
		 * If set, little endian, if unset, assumed to be big endian.
		 */
		Endieness(0);

		private int offset;

		Flag(int offset)
		{
			this.offset = offset;
		}
	}

	public static final byte[] V_0_2 = U.toBytes("AERIS-COMM-0002");

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
					/* Wait until we've gotten the version data */
					for (byte b : ver)
					{
						int cur = input.read();
						if (cur == -1)
							return null;
						if (cur != b)
							continue main;
					}
					/* Wait until we've gotten the rest of the header */
					while (input.available() < headLen - ver.length)
						U.sleep(5);
					/*
					 * read the rest of the header, since we've already read the version
					 */
					data = new byte[headLen];
					if (input.read(data, ver.length, headLen - ver.length) != headLen - ver.length)
						continue;
					/* backfill the version data */
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
					} catch (DecodingException e)
					{
						U.e("Got malformed communique while parsing header: " + e.getMessage());
						continue;
					}

					List<CommuniqueField> fields = new ArrayList<>(c.fieldCount);
					for (int i = 0; i < c.fieldCount; i++)
					{
						short type = input.readShort();
						short encoding = input.readShort();
						short encryption = input.readShort();
						int size = input.readInt();
						fields.add(new CommuniqueField(i, type, encoding, encryption, size));
					}

					for (CommuniqueField f : fields)
					{
						data = new byte[f.getSize()];
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

	/**
	 * @return the current version of the Communique.
	 */
	public static byte[] getCurrentVersion()
	{
		return Arrays.copyOf(Communique.V_0_2, Communique.V_0_2.length);
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
		// Encryption method
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
		// flags
		res += Integer.BYTES;
		// field count
		res += Integer.BYTES;
		return res;
	}

	/**
	 * @param data
	 * @return a new Communique with one field representing the provided data
	 */
	public static Communique of(byte[] data)
	{
		return new Communique().add(data);
	}

	/**
	 * @param s
	 * @return a new Communique with one field representing the provided data
	 */
	public static Communique of(String s)
	{
		return new Communique().add(s);
	}

	private byte[]	version	= Communique.getCurrentVersion();
	private int		flags;

	private int fieldCount;

	private List<CommuniqueField> fields;

	private boolean readOnly = false;

	private Instant	sentTime;
	private Instant	creationTime	= Instant.now();

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

		ensureValidCapacityForFields(data);

		this.fields = extractFields(data);
	}

	/**
	 * Adds a new field to this Communique representing the given binary blob.
	 *
	 * @param data
	 * @return this object
	 */
	public Communique add(byte[] data)
	{
		this.add(Datatype.BinaryBlob, Encoding.getDefault(), Encryption.Unencrypted, ByteBuffer.wrap(data));
		return this;
	}

	/**
	 * Adds a new field to this Communique representing the given binary blob.
	 *
	 * @param data
	 * @param modifier
	 *            Called to allow modification (such as encryption) of the newly constructed CommuniqueField.
	 * @return this object
	 */
	public Communique add(byte[] data, Consumer<CommuniqueField> modifier)
	{
		this.add(data);
		modifier.accept(this.fields.get(this.fields.size() - 1));
		return this;
	}

	/**
	 * Adds a new field to this Communique representing the given binary blob.
	 *
	 * @param data
	 * @param enc
	 * @return this object
	 */
	public Communique add(byte[] data, Encoding enc)
	{
		this.add(Datatype.String, enc, Encryption.Unencrypted, ByteBuffer.wrap(data));
		return this;
	}

	private Communique add(Datatype datType, Encoding enc, Encryption crypt, ByteBuffer data)
	{
		if (this.readOnly)
			throw new EncodingException("Please do not modify an existing communique.");
		this.fieldCount++;
		this.fields.add(new CommuniqueField(this.fields.size(), datType.getId(), enc.getId(), crypt.getId(), data));
		return this;
	}

	/**
	 * Adds a new field to this Communique representing the given String.
	 *
	 * @param data
	 * @return this object
	 */
	public Communique add(String data)
	{
		this.add(Datatype.String, Encoding.getDefault(), Encryption.Unencrypted, U.toBuff(data));
		return this;
	}

	/**
	 * @param data
	 * @param modifier
	 * @return this object
	 */
	public Communique add(String data, Consumer<CommuniqueField> modifier)
	{
		this.add(data);
		modifier.accept(this.fields.get(this.fields.size() - 1));
		return this;
	}

	/**
	 * @param data
	 * @param enc
	 * @return this object
	 */
	public Communique add(String data, Encoding enc)
	{
		this.add(Datatype.String, enc, Encryption.Unencrypted, U.toBuff(data));
		return this;
	}

	public byte[] bytes()
	{
		return compile().array();
	}

	private ByteBuffer compile()
	{
		int msgSize = 0;
		msgSize += Communique.getMinHeaderSize();
		msgSize += this.fieldCount * Communique.getMinFieldDefSize();
		msgSize += this.fields.stream().mapToInt(CommuniqueField::getSize).sum();
		ByteBuffer res = ByteBuffer.allocate(msgSize);
		res.order(flag(Flag.Endieness) ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);

		// header data
		res.put(Communique.getCurrentVersion());
		Instant now = Instant.now();
		res.putLong(now.getEpochSecond());
		res.putInt(now.getNano());
		res.putInt(this.flags);
		res.putInt(this.fieldCount);

		// field data
		this.fields.forEach(f -> {
			f.compile(res);
		});

		this.fields.forEach(f -> {
			f.data().rewind();
			res.put(f.data());
		});

		return res;
	}

	/**
	 * @param index
	 * @return the binary data of the field at the given index.
	 */
	public byte[] data(int index)
	{
		ByteBuffer b = this.fields.get(index).data();
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
			short encryption = data.getShort();
			int size = data.getInt();
			data.mark();
			data.position(dataStart);
			ByteBuffer curData = ((ByteBuffer) data.duplicate().limit(size)).slice();
			dataStart += size;
			data.reset();
			res.add(new CommuniqueField(i, type, encoding, encryption, size, curData));
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
	 * @return the time this object was created. For Communiques that are received by the system, this is the time that
	 *         the header data was first parsed.
	 */
	public Instant getCreationTime()
	{
		return this.creationTime;
	}

	/**
	 * @return A list of all fields.
	 */
	public List<CommuniqueField> getFields()
	{
		return this.fields;
	}

	/**
	 * @return the reported <i>send</i> time of this Communique. This value cannot be verified for Communiques that are
	 *         received by the system, but will always be accurate for Communiques that the system sends.
	 */
	public Instant getTimestamp()
	{
		return this.sentTime;
	}

	private void parseHeaderData(ByteBuffer data) throws DecodingException
	{
		// Parse header data
		if (data.remaining() < Communique.getMinHeaderSize())
			throw new DecodingException("Insufficient data, header too small.");
		this.version = new byte[Communique.getCurrentVersion().length];
		data.get(this.version);
		long epochSecond = data.getLong();
		int nanos = data.getInt();
		this.sentTime = Instant.ofEpochSecond(epochSecond, nanos);
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
			sb.append(' ').append(f.getDatatype()).append(' ').append(f.getEncoding()).append('[').append(f.getSize()).append(']');
			if (f.getDatatype().equals(Datatype.String))
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