package silentcrypt.core.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * a holding class for public/private parameter pairs.
 */
public class RsaKeyPair extends AsymmetricCipherKeyPair
{
	public RsaKeyPair(RSAKeyParameters publicParam, RSAKeyParameters privateParam)
	{
		super(publicParam, privateParam);
	}

	public RSAKeyParameters getPublicRsa()
	{
		return U.quietCast(getPublic());
	}

	public RSAKeyParameters getPrivateRsa()
	{
		return U.quietCast(getPrivate());
	}
}
