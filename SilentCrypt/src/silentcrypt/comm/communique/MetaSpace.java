package silentcrypt.comm.communique;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.util.U;

public class MetaSpace
{
	public static class MetaKey<T>
	{
		String name;

		public MetaKey(String name)
		{
			this.name = name;
		}
	}

	public static final MetaKey<RSAKeyParameters>	RSA_KEY	= new MetaKey<>("rsa_key_data");
	public static final MetaKey<byte[]>				AES_KEY	= new MetaKey<>("aes_key_data");
	// as many as needed, shouldn't be too many

	private Map<MetaKey<?>, Object> data;

	public MetaSpace()
	{
		this.data = new HashMap<>();
	}

	public <T> T get(MetaKey<T> key) throws IllegalStateException
	{
		if (!this.data.containsKey(key))
			throw new IllegalStateException("No data found for " + key.name);
		return U.quietCast(this.data.get(key));
	}

	public <T> MetaSpace set(MetaKey<T> key, T value)
	{
		this.data.put(key, value);
		return this;
	}

	public MetaSpace(MetaSpace other)
	{
		this.data = other.data;
	}
}