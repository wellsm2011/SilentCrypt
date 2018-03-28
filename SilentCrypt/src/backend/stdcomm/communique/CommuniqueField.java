package backend.stdcomm.communique;

import java.nio.ByteBuffer;

public class CommuniqueField
{
	private int			fieldIndex;
	private Datatype	datatype;
	private Encoding	encoding;
	private int			size;
	private ByteBuffer	data;

	CommuniqueField(int fieldIndex, short datatype, short encoding, int size)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = Datatype.get(datatype);
		this.encoding = Encoding.get(encoding);
		this.size = size;
	}

	CommuniqueField(int fieldIndex, short datatype, short encoding, int size, ByteBuffer data)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = Datatype.get(datatype);
		this.encoding = Encoding.get(encoding);
		this.size = size;
		this.data = data.asReadOnlyBuffer();
	}

	void compile(ByteBuffer res)
	{
		res.putShort(this.datatype.getId());
		res.putShort(this.encoding.getId());
		res.putInt(this.size);
	}

	public ByteBuffer data()
	{
		return this.data;
	}

	public Datatype getDatatype()
	{
		return this.datatype;
	}

	public Encoding getEncoding()
	{
		return this.encoding;
	}

	public int getFieldIndex()
	{
		return this.fieldIndex;
	}

	public int getSize()
	{
		return this.size;
	}

	void setData(ByteBuffer data)
	{
		this.data = data.asReadOnlyBuffer();
	}
}