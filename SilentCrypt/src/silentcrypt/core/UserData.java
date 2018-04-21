package silentcrypt.core;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Consumer;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.communique.Communique;
import silentcrypt.util.RsaUtil;

public class UserData
{
	private RSAKeyParameters		publicKey;
	private byte[]					certificate	= null;
	private String					username;
	private Instant					lastMessage;
	private long					connectionId;
	private Consumer<Communique>	reply;

	public UserData(String username, RSAKeyParameters publicKey, Instant lastMessage, long connectionId, Consumer<Communique> reply)
	{
		this.username = username;
		this.publicKey = publicKey;
		this.lastMessage = lastMessage;
		this.connectionId = connectionId;
		this.reply = reply;
	}

	public void setCert(byte[] cert, RSAKeyParameters caKey)
	{
		try
		{
			byte[] plainCert = RsaUtil.decrypt(cert, caKey);
			if (Objects.equals(RsaUtil.fromBytes(plainCert), (this.publicKey)))
				this.certificate = cert;
			else
				throw new IllegalArgumentException("Signed certificate does not match given certificate.");
		} catch (InvalidCipherTextException e)
		{
			throw new IllegalArgumentException("Signed certificate does not match given certificate.", e);
		}
	}

	public boolean hasCert()
	{
		return this.certificate != null;
	}

	public byte[] getCert()
	{
		return this.certificate;
	}

	public RSAKeyParameters getPublicKey()
	{
		return this.publicKey;
	}

	public String getUsername()
	{
		return this.username;
	}

	public Instant getLastMessage()
	{
		return this.lastMessage;
	}

	public long getConnectionId()
	{
		return this.connectionId;
	}

	UserData updateLastMessage(Instant instant)
	{
		this.lastMessage = instant;
		return this;
	}

	UserData updateReply(Consumer<Communique> reply)
	{
		this.reply = reply;
		return this;
	}

	public UserData replyTo(Communique message)
	{
		this.reply.accept(message);
		return this;
	}
}