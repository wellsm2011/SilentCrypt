package silentcrypt.core;

import java.math.BigInteger;
import java.time.Instant;
import java.util.function.Consumer;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.communique.Communique;

public class UserData
{
	private RSAKeyParameters		publicKey;
	private String					username;
	private Instant					lastMessage;
	private BigInteger				connectionId;
	private Consumer<Communique>	reply;

	public UserData(String username, RSAKeyParameters publicKey, Instant lastMessage, BigInteger connectionId, Consumer<Communique> reply)
	{
		this.username = username;
		this.publicKey = publicKey;
		this.lastMessage = lastMessage;
		this.connectionId = connectionId;
		this.reply = reply;
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

	public BigInteger getConnectionId()
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