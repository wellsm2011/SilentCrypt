package silentcrypt.core;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.Datatype;
import silentcrypt.comm.communique.Encoding;
import silentcrypt.comm.communique.MetaSpace;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.comm.server.ServerConn;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.U;

public class CommClient extends CommBase
{
	private ServerConn server;

	public CommClient(String username, RsaKeyPair myKey, InetSocketAddress addr, InetSocketAddress caAddr) throws TimeoutException, MessageRejectedException
	{
		super(username, myKey);
		if (addr.getPort() == 0)
			addr = new InetSocketAddress(addr.getAddress(), CommBase.DEFAULT_PORT);

		registerWithCa(caAddr);

		Communique authReq = MessageType.AUTHENTICATION_REQUEST.create(username);
		authReq.add(myKey.getPublicRsa()).add(this.me.getCert());

		this.server = ServerConn.get(addr).listen(this::processMsg).send(authReq);

		listen(this::processMessageReject, MessageType.MESSAGE_REJECT);
		listen(this::processInformationResponse, MessageType.INFORMATION_RESPONSE);
		listen(this::processChannelJoinAuthentication, MessageType.CHANNEL_JOIN_AUTHENTICATION);
		listen(this::processAuthenticationResponse, MessageType.AUTHENTICATION_RESPONSE);
		listen(this::processChannelLeaveNotice, MessageType.CHANNEL_LEAVE_NOTICE);
		listen(this::processChannelCreationAnnouncement, MessageType.CHANNEL_CREATION_ANNOUNCEMENT);
		listen(this::processChannelJoinAnnouncement, MessageType.CHANNEL_JOIN_ANNOUNCEMENT);
		listen(this::processChannelLeaveAnnouncement, MessageType.CHANNEL_LEAVE_ANNOUNCEMENT);
		listen(this::processServerJoinAnnouncement, MessageType.SERVER_JOIN_ANNOUNCEMENT);
		listen(this::processServerLeaveAnnouncement, MessageType.SERVER_LEAVE_ANNOUNCEMENT);
	}

	private void processMessageReject(Communique msg)
	{
		U.e(MessageType.get(msg.getField(4).data(Integer.class)) + " rejected: " + msg.getField(2).data(String.class));
	}

	private void processInformationResponse(Communique msg)
	{
		String channel = msg.getField(2).data(String.class);
		if (!channel.isEmpty())
		{
			Channel chan = this.activeChannels.get(channel);
			if (chan == null)
			{
				chan = new Channel(channel);
				this.activeChannels.put(channel, chan);
			}
			chan.clearUsers();

			// Listing clients in the channel.
			for (int i = 3; i < msg.fieldCount(); i += 2)
			{
				String username = msg.getField(i).data(String.class);
				RSAKeyParameters key = msg.getField(i + 1).data(RSAKeyParameters.class);

				UserData ud = this.connectedUsers.get(username);
				if (ud == null)
				{
					ud = new UserData(username, key, msg.getTimestamp(), -1, this.server::send);
					this.connectedUsers.put(username, ud);
				}
				chan.ensureContains(ud);
			}
		} else
		{
			for (int i = 3; i < msg.fieldCount(); i++)
			{
				String channelName = msg.getField(i).data(String.class);
				if (!this.activeChannels.containsKey(channelName))
					this.activeChannels.put(channelName, new Channel(channelName));
			}
		}
	}

	private void processChannelJoinAuthentication(Communique msg)
	{
		Communique acceptJoin = MessageType.CHANNEL_JOIN_ACCEPT.create(this.me.getUsername());
	}

	private void processAuthenticationResponse(Communique msg)
	{

	}

	private void processChannelLeaveNotice(Communique msg)
	{

	}

	private void processChannelCreationAnnouncement(Communique msg)
	{

	}

	private void processChannelJoinAnnouncement(Communique msg)
	{

	}

	private void processChannelLeaveAnnouncement(Communique msg)
	{

	}

	private void processServerJoinAnnouncement(Communique msg)
	{

	}

	private void processServerLeaveAnnouncement(Communique msg)
	{

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
		this.server.send(c);
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
		this.server.send(c);
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
