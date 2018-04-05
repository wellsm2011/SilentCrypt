package silentcrypt.comm.net.communique;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import silentcrypt.util.U;

/**
 * @author Michael
 */
public enum Encryption
{
	Unencrypted(0),
	Aes256(1),
	Rsa4096(2);

	private static final Map<Short, Encryption> reverse;

	static
	{
		reverse = Collections.unmodifiableMap(Arrays.stream(Encryption.values()).collect(Collectors.toMap(d -> d.getId(), d -> d)));
	}

	public static Encryption get(short id)
	{
		Encryption res = Encryption.reverse.get(id);
		if (res == null)
		{
			U.e("Error, unknown datatype " + id + "  defaulting to Unencrypted");
			return Unencrypted;
		}
		return res;
	}

	public static boolean isKnown(short id)
	{
		return Encryption.reverse.containsKey(id);
	}

	private short id;

	private Encryption(int id)
	{
		this.id = (short) id;
	}

	public short getId()
	{
		return this.id;
	}
}
