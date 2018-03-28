package silentcrypt.core.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/**
 * a holding class for public/private parameter pairs.
 */
public class RsaKeyPair
{
	private RSAKeyParameters	publicParam;
	private RSAKeyParameters	privateParam;

	public RsaKeyPair(RSAKeyParameters publicParam, RSAKeyParameters privateParam)
	{
		this.publicParam = publicParam;
		this.privateParam = privateParam;
	}

	public RSAKeyParameters getPublic()
	{
		return this.publicParam;
	}

	public RSAKeyParameters getPrivate()
	{
		return this.privateParam;
	}

	public AsymmetricCipherKeyPair toCipherKeyPair()
	{
		return new AsymmetricCipherKeyPair(this.publicParam, this.privateParam);
	}
}
