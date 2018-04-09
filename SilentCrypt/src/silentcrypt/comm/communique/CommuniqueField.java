package silentcrypt.comm.communique;

import java.nio.ByteBuffer;
import java.time.Instant;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.util.AesUtil;
import silentcrypt.util.BinaryData;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

/**
 * Represents an individual field in a Communique.
 *
 * @see silentcrypt.comm.communique.Communique
 * @author Andrew Binns Binns
 * @author Michael Wells Wells
 */
public class CommuniqueField
{
	private int			fieldIndex;
	private Datatype	datatype;
	private Encoding	encoding;
	private Encryption	encryption;
	private int			size;
	private ByteBuffer	data;

	CommuniqueField(int fieldIndex, short datatype, short encoding, short encryption, ByteBuffer data)
	{
		this(fieldIndex, datatype, encoding, encryption, data.remaining(), data);
	}

	CommuniqueField(int fieldIndex, short datatype, short encoding, short encryption, int size)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = Datatype.get(datatype);
		this.encoding = Encoding.get(encoding);
		this.encryption = Encryption.get(encryption);
		this.size = size;
	}

	CommuniqueField(int fieldIndex, short datatype, short encoding, short encryption, int size, ByteBuffer data)
	{
		this.fieldIndex = fieldIndex;
		this.datatype = Datatype.get(datatype);
		this.encoding = Encoding.get(encoding);
		this.encryption = Encryption.get(encryption);
		this.size = size;
		this.data = data.asReadOnlyBuffer();
	}

	void compile(ByteBuffer res)
	{
		res.putShort(this.datatype.getId());
		res.putShort(this.encoding.getId());
		res.putShort(this.encryption.getId());
		res.putInt(this.size);
	}

	/**
	 * @param aesKey
	 * @throws InvalidCipherTextException
	 *             If there is a problem in the underlying encryption framework.
	 * @throws IllegalStateException
	 *             If this communique field is not encrypted using AES.
	 */
	public BinaryData decrypt(BinaryData aesKey) throws InvalidCipherTextException, IllegalStateException
	{
		if (this.encryption != Encryption.Aes256)
			throw new IllegalStateException("Can't decrypt with " + Encryption.Aes256 + "; data is " + this.encryption + ".");
		return AesUtil.decrypt(BinaryData.fromBuffer(this.data), aesKey);
	}

	/**
	 * Attempts to decrypt this field using the given RSA key.
	 *
	 * @see silentcrypt.util.RsaUtil#decrypt(BinaryData, RSAKeyParameters)
	 * @param rsaKey
	 * @throws InvalidCipherTextException
	 *             If there is a problem in the underlying encryption framework.
	 * @throws IllegalStateException
	 *             If this communique field is not encrypted using RSA.
	 */
	public BinaryData decrypt(RSAKeyParameters rsaKey) throws InvalidCipherTextException, IllegalStateException
	{
		if (this.encryption != Encryption.Rsa4096)
			throw new IllegalStateException("Can't decrypt with " + Encryption.Rsa4096 + "; data is " + this.encryption + ".");
		return RsaUtil.decrypt(BinaryData.fromBuffer(this.data), rsaKey);
	}

	/**
	 * @return A read only ByteBuffer containing the data in this field.
	 */
	public ByteBuffer data()
	{
		// Ensure nobody changes our original data buffer.
		return this.data.asReadOnlyBuffer();
	}

	/**
	 * @return This field's data as a raw byte array. Note that if this field is currently encrypted, this function will
	 *         return encrypted data.
	 */
	public byte[] dataArray()
	{
		this.data.mark();
		byte[] ret = new byte[this.data.remaining()];
		this.data.get(ret);
		this.data.reset();
		return ret;
	}

	public String dataString() throws IllegalStateException
	{
		if (this.datatype != Datatype.String)
			throw new IllegalStateException("Field is not a string.");
		return U.toString(dataArray());
	}

	public Instant dataInstant() throws IllegalStateException
	{
		if (this.datatype != Datatype.Instant)
			throw new IllegalStateException("Field is not an instant.");
		return U.toInstant(data());
	}

	public boolean dataEquals(String data)
	{
		return dataEquals(U.toBytes(data));
	}

	public boolean dataEquals(byte[] data)
	{
		return this.dataEquals(ByteBuffer.wrap(data));
	}

	public boolean dataEquals(ByteBuffer data)
	{
		return this.data.compareTo(data) == 0;
	}

	/**
	 * @param oth
	 * @return true iff the other CommuniqueField contains the same data with the same encryption.
	 */
	public boolean equals(CommuniqueField oth)
	{
		if (oth == null)
			return false;
		if (oth.size != this.size)
			return false;
		if (oth.datatype != this.datatype)
			return false;
		if (oth.encoding != this.encoding)
			return false;
		if (oth.encryption != this.encryption)
			return false;
		return this.dataEquals(oth.data);
	}

	@Override
	public boolean equals(Object o)
	{
		if (o instanceof CommuniqueField)
			return this.equals((CommuniqueField) o);
		return false;
	}

	/**
	 * @return The data type stored in this field.
	 */
	public Datatype getDatatype()
	{
		return this.datatype;
	}

	/**
	 * @return The encoding used to serialize this field. (Note: This does not describe the charset used for encoding
	 *         strings, but rather the type and level of compression used on the binary data)
	 */
	public Encoding getEncoding()
	{
		return this.encoding;
	}

	/**
	 * @return
	 */
	public Encryption getEncryption()
	{
		return this.encryption;
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
		this.data = data;
	}

}