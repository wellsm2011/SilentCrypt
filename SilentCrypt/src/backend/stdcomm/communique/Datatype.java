package backend.stdcomm.communique;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import silentcrypt.core.util.U;

public enum Datatype
{
	BinaryBlob(0),
	String(1);

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

	public static boolean isKnown(short id)
	{
		return Datatype.reverse.containsKey(id);
	}

	private short id;

	Datatype(int id)
	{
		this.id = (short) id;
	}

	public short getId()
	{
		return this.id;
	}
}