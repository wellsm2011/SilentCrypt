package silentcrypt.comm.communique;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import silentcrypt.util.U;

/**
 * Represents the specific type of data contained in a CommuniqueField.
 *
 * @author Andrew Binns
 * @author Michael Wells
 */
public enum Datatype
{
	/**
	 * Represents purely binary data.
	 */
	BinaryBlob(0),
	/**
	 * Represents a String.
	 */
	String(1),
	/**
	 * Represents a moment in time.
	 */
	Instant(2);

	private static final Map<Short, Datatype> reverse;

	static
	{
		reverse = Collections.unmodifiableMap(Arrays.stream(Datatype.values()).collect(Collectors.toMap(d -> d.getId(), d -> d)));
	}

	public static Datatype get(short id)
	{
		Datatype res = Datatype.reverse.get(id);
		if (res == null)
		{
			U.e("Error, unknown datatype " + id + "  defaulting to Binary Blob");
			return BinaryBlob;
		}
		return res;
	}

	/**
	 * @param id
	 * @return true if the given id is known by this version of the enum class.
	 */
	public static boolean isKnown(short id)
	{
		return Datatype.reverse.containsKey(id);
	}

	private short id;

	private Datatype(int id)
	{
		this.id = (short) id;
	}

	/**
	 * @return the encoding id for this Datatype. Used when serializing fields.
	 */
	public short getId()
	{
		return this.id;
	}
}