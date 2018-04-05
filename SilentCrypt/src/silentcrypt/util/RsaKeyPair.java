package silentcrypt.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * A holding class for public/private parameter pairs. BouncyCastle needs to start using generics...
 *
 * @author Michael
 */
public class RsaKeyPair extends AsymmetricCipherKeyPair
{
	public RsaKeyPair(RSAKeyParameters publicParam, RSAKeyParameters privateParam)
	{
		super(publicParam, privateParam);
	}

	public RSAKeyParameters getPrivateRsa()
	{
		return U.quietCast(getPrivate());
	}

	public RSAKeyParameters getPublicRsa()
	{
		return U.quietCast(getPublic());
	}
}
