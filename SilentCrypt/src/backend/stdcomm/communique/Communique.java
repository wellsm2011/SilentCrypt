package backend.stdcomm.communique;

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
import java.util.function.Supplier;

import backend.stdcomm.exception.DecodingException;
import backend.stdcomm.exception.EncodingException;
import silentcrypt.core.util.U;

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

	public static final byte[] V_0_1 = "AERISV001".getBytes();

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
						int size = input.readInt();
						fields.add(new CommuniqueField(i, type, encoding, size));
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

	public static byte[] getCurrentVersion()
	{
		return Arrays.copyOf(Communique.V_0_1, Communique.V_0_1.length);
	}

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

	public static Communique of(byte[] data)
	{
		return new Communique().add(data);
	}

	public static Communique of(String s)
	{
		return new Communique().add(s);
	}

	private byte[]	version	= getCurrentVersion();
	private int		flags;

	private int fieldCount;

	private List<CommuniqueField> fields;

	private boolean readOnly;

	private Instant sentTime;

	public Communique()
	{
		this.fields = new ArrayList<>();
		this.readOnly = false;
	}

	public Communique(ByteBuffer data) throws DecodingException
	{
		this.readOnly = true;
		parseHeaderData(data);

		ensureValidCapacityForFields(data);

		this.fields = extractFields(data);
	}

	public Communique add(byte[] data)
	{
		this.add(Datatype.BinaryBlob, Encoding.getDefault(), ByteBuffer.wrap(data));
		return this;
	}

	public Communique add(byte[] data, Encoding enc)
	{
		this.add(Datatype.String, enc, ByteBuffer.wrap(data));
		return this;
	}

	public Communique add(Datatype datType, Encoding enc, ByteBuffer data)
	{
		if (this.readOnly)
			throw new EncodingException("Please do not modify an existing communique.");
		this.fieldCount++;
		this.fields.add(new CommuniqueField(this.fields.size(), datType.getId(), enc.getId(), data.capacity(), data));
		return this;
	}

	public Communique add(String data)
	{
		this.add(Datatype.String, Encoding.getDefault(), U.toBuff(data));
		return this;
	}

	public Communique add(String data, Encoding enc)
	{
		this.add(Datatype.String, enc, U.toBuff(data));
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
			int size = data.getInt();
			data.mark();
			data.position(dataStart);
			ByteBuffer curData = ((ByteBuffer) data.duplicate().limit(size)).slice();
			dataStart += size;
			data.reset();
			res.add(new CommuniqueField(i, type, encoding, size, curData));
		}
		return res;
	}

	public int fieldCount()
	{
		return this.fieldCount;
	}

	private boolean flag(Flag flag)
	{
		return (this.flags & 1 << flag.offset) > 0;
	}

	public List<CommuniqueField> getFields()
	{
		return this.fields;
	}

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

	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder();

		sb.append("Communique ");
		sb.append("Version:").append(new String(this.version)).append(' ');
		sb.append("FieldCount:").append(this.fieldCount);

		for (Flag f : Flag.values())
			sb.append(' ').append(f.toString() + ":").append(flag(f));
		for (CommuniqueField f : this.fields)
		{
			sb.append(' ').append(f.getDatatype()).append(' ').append(f.getEncoding()).append('[').append(f.getSize()).append(']');
			if (f.getDatatype().equals(Datatype.String))
				sb.append(' ').append(new String(data(f.getFieldIndex())));
		}

		return sb.toString();
	}

	public void write(OutputStream out) throws IOException
	{
		ByteBuffer data = compile();
		out.write(data.array());
	}
}
