package silentcrypt.core;

import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.Datatype;
import silentcrypt.comm.communique.Encoding;
import silentcrypt.comm.communique.MetaSpace;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.util.RsaKeyPair;

public class CommClient extends CommBase
{
	public CommClient(String username, RsaKeyPair myKey) throws TimeoutException, MessageRejectedException
	{
		super(username, myKey);
	}

	public void sendChannelMessage(String channel, byte[] data)
	{
		byte[] channelKey = this.channelKeys.get(channel);
		if (channelKey == null)
			throw new IllegalArgumentException("Unknown channel: " + channel);
		Communique c = MessageType.CHANNEL_MESSAGE.create(this.me.getUsername());
		c.add(channel).add(Datatype.BINARY_BLOB, Encoding.Aes, data);
		c.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey).set(MetaSpace.AES_KEY, channelKey);
		c.sign();
		this.replyToServer.accept(c);
	}

	public void sendUserMessage(String username, byte[] data)
	{
		UserData user = this.connectedUsers.get(username);
		if (user == null)
			throw new IllegalArgumentException("Unknown user: " + username);
		Communique c = MessageType.CLIENT_MESSAGE.create(this.me.getUsername());
		c.add(username).add(Datatype.BINARY_BLOB, Encoding.RsaEncrypt, data);
		c.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey).set(MetaSpace.RSA_EXTERN, user.getPublicKey());
		c.sign();
		this.replyToServer.accept(c);
	}

	public CommClient listenToChannels(BiConsumer<String, byte[]> listener)
	{
		listen(c -> {
			c.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
			String channel = c.getField(1).data(String.class);
			byte[] data = c.getField(3).data(byte[].class);
			listener.accept(channel, data);
		}, MessageType.CLIENT_MESSAGE);
		return this;
	}

	public CommClient listenToUsers(BiConsumer<String, byte[]> listener)
	{
		listen(c -> {
			c.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
			String username = c.getField(1).data(String.class);
			byte[] data = c.getField(3).data(byte[].class);
			listener.accept(username, data);
		}, MessageType.CHANNEL_MESSAGE);
		return this;
	}
}
