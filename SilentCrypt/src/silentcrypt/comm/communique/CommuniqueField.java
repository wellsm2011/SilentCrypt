package silentcrypt.comm.communique;

import java.nio.ByteBuffer;

import silentcrypt.comm.exception.DecodingException;
import silentcrypt.comm.exception.EncodingException;
import silentcrypt.util.U;

/**
 * Represents an individual field in a Communique.
 *
 * @see silentcrypt.comm.communique.Communique
 * @author Andrew Binns
 * @author Michael Wells
 */
public class CommuniqueField
{
	private int			fieldIndex;
	private Datatype<?>	datatype;
	private Encoding	encoding;
	private Object		data		= null;
	private ByteBuffer	encodedData	= null;

	private transient MetaSpace metaSpace;

	// New field.
	<T> CommuniqueField(MetaSpace ms, int fieldIndex, Datatype<T> datatype, Encoding encoding, T data)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = datatype;
		this.encoding = encoding;
		this.data = data;
		this.metaSpace = ms;
	}

	// From input stream.
	CommuniqueField(MetaSpace ms, int fieldIndex, short datatype, short encoding)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = Datatype.get(datatype);
		this.encoding = Encoding.get(encoding);
		this.data = null;
		this.metaSpace = ms;
	}

	// From buffer.
	CommuniqueField(MetaSpace ms, int fieldIndex, short datatype, short encoding, ByteBuffer data)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = Datatype.get(datatype);
		this.encoding = Encoding.get(encoding);
		this.encodedData = data.asReadOnlyBuffer();
		this.metaSpace = ms;
	}

	Object ensureData() throws DecodingException
	{
		if (this.data == null)
			this.data = this.datatype.decode(this.encoding.decode(this.encodedData, this.metaSpace));
		return this.data;
	}

	ByteBuffer ensureEncodedData() throws EncodingException
	{
		if (this.encodedData == null)
			this.encodedData = this.encoding.encode(this.datatype.encode(U.quietCast(this.data)), this.metaSpace);
		return this.encodedData;
	}

	void compile(ByteBuffer res) throws EncodingException
	{
		res.putShort(this.datatype.getId());
		res.putShort(this.encoding.getId());
		res.putInt(ensureEncodedData().remaining());
	}

	/**
	 * @return The data type stored in this field.
	 */
	public Datatype<?> getDatatype()
	{
		return this.datatype;
	}

	public <T> T data(Class<T> clazz) throws DecodingException
	{
		ensureData();
		if (clazz.isAssignableFrom(this.datatype.getDataClass()))
			return U.quietCast(this.data);
		throw new ClassCastException("Cannot cast " + this.datatype.getDataClass().getCanonicalName() + " to " + clazz.getCanonicalName() + ".");
	}

	/**
	 * @return the MetaSpace for the Communique attached to this field.
	 */
	public MetaSpace getMetaSpace()
	{
		return this.metaSpace;
	}

	/**
	 * Sets this field's meta space, which is used for encoding and decoding.
	 *
	 * @param ms
	 */
	void setMetaSpace(MetaSpace ms)
	{
		this.metaSpace = ms;
	}

	/**
	 * @return A read only ByteBuffer containing the data in this field.
	 */
	public ByteBuffer encodedData()
	{
		// Ensure nobody changes our original data buffer.
		return ensureEncodedData().asReadOnlyBuffer();
	}

	/**
	 * @return The encoding used to serialize this field. (Note: This does not describe the charset used for encoding
	 *         strings, but rather the type and level of compression used on the binary data)
	 */
	public Encoding getEncoding()
	{
		return this.encoding;
	}

	public int getFieldIndex()
	{
		return this.fieldIndex;
	}

	public int getEncodedSize() throws EncodingException
	{
		return ensureEncodedData().remaining();
	}

	void setData(ByteBuffer data)
	{
		this.encodedData = data.asReadOnlyBuffer();
	}
}