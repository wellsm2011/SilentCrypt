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
import silentcrypt.util.AesUtil;
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
		authReq.getMetaSpace().set(MetaSpace.RSA_SELF, myKey);

		this.server = ServerConn.get(addr).listen(this::processMsg).send(authReq);

		listen(this::processMessageReject, MessageType.MESSAGE_REJECT);
		listen(this::processInformationResponse, MessageType.INFORMATION_RESPONSE);
		listen(this::processChannelJoinAuthentication, MessageType.CHANNEL_JOIN_AUTHENTICATION);
		listen(this::processChannelJoinAccept, MessageType.CHANNEL_JOIN_ACCEPT);
		listen(this::processAuthenticationResponse, MessageType.AUTHENTICATION_RESPONSE);
		listen(this::processChannelCreationAnnouncement, MessageType.CHANNEL_CREATION_ANNOUNCEMENT);
		listen(this::processChannelJoinAnnouncement, MessageType.CHANNEL_JOIN_ANNOUNCEMENT);
		listen(this::processChannelLeaveAnnouncement, MessageType.CHANNEL_LEAVE_ANNOUNCEMENT);
		listen(this::processServerJoinAnnouncement, MessageType.SERVER_JOIN_ANNOUNCEMENT);
		listen(this::processServerLeaveAnnouncement, MessageType.SERVER_LEAVE_ANNOUNCEMENT);

		Communique infoReq = MessageType.INFORMATION_REQUEST.create(username);
		infoReq.getMetaSpace().set(MetaSpace.RSA_SELF, myKey);
		this.server.send(infoReq);
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
		String username = msg.getField(1).data(String.class);
		String channelname = msg.getField(2).data(String.class);
		UserData user = this.connectedUsers.get(username);
		if (user == null)
		{
			rejectChannelJoinAuth(username, channelname);
			return;
		}

		Channel channel = this.activeChannels.get(channelname);
		if (channel == null || channel.getKey() == null)
		{
			rejectChannelJoinAuth(username, channelname);
			return;
		}
		Communique acceptJoin = MessageType.CHANNEL_JOIN_ACCEPT.create(this.me.getUsername());
		acceptJoin.add(channelname).add(username).add(Encoding.RsaEncrypt, channel.getKey());
		acceptJoin.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey).set(MetaSpace.RSA_EXTERN, user.getPublicKey());
		this.server.send(acceptJoin.sign());
	}

	private void rejectChannelJoinAuth(String channelName, String client)
	{
		Communique msg = MessageType.CHANNEL_JOIN_REJECT.create(this.me.getUsername());
		msg.add(channelName).add(client).getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
		this.server.send(msg.sign());
	}

	private void processChannelJoinAccept(Communique msg)
	{
		msg.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
		String chanName = msg.getField(2).data(String.class);
		Channel chan = this.activeChannels.get(chanName);
		if (chan == null)
		{
			chan = new Channel(chanName);
			chan.users.put(this.me.getUsername(), this.me);
		}
		chan.setKey(msg.getField(4).data(byte[].class));
	}

	private void processAuthenticationResponse(Communique msg)
	{
		processServerJoinAnnouncement(msg);
	}

	private void processChannelCreationAnnouncement(Communique msg)
	{
		Channel channel = new Channel(msg.getField(2).data(String.class));
		UserData user = this.connectedUsers.get(msg.getField(3).data(String.class));
		this.activeChannels.put(channel.getName(), channel);
		if (user != null)
			channel.ensureContains(user);
	}

	private void processChannelJoinAnnouncement(Communique msg)
	{
		String channel = msg.getField(2).data(String.class);
		Channel c = this.activeChannels.get(channel);
		if (c == null)
		{
			c = new Channel(channel);
			this.activeChannels.put(channel, c);
		}
		UserData user = this.connectedUsers.get(msg.getField(1).data(String.class));
		if (user != null)
			c.users.put(user.getUsername(), user);
	}

	private void processChannelLeaveAnnouncement(Communique msg)
	{
		Channel channel = this.activeChannels.get(msg.getField(2).data(String.class));
		if (channel != null)
			channel.users.remove(this.connectedUsers.get(msg.getField(1).data(String.class)));
	}

	private void processServerJoinAnnouncement(Communique msg)
	{
		String username = msg.getField(1).data(String.class);
		RSAKeyParameters publicKey = msg.getField(2).data(RSAKeyParameters.class);
		byte[] cert = msg.getField(3).data(byte[].class);
		UserData user = new UserData(username, publicKey, msg.getTimestamp(), -1, this.server::send);
		user.setCert(cert, this.caPublic);
		this.connectedUsers.put(username, user);
	}

	private void processServerLeaveAnnouncement(Communique msg)
	{
		String username = msg.getField(1).data(String.class);
		this.connectedUsers.remove(username);
		this.activeChannels.values().forEach(c -> c.users.remove(username));
	}

	public void sendChannelMessage(String channel, byte[] data)
	{
		Channel chan = this.activeChannels.get(channel);
		if (chan == null)
			throw new IllegalArgumentException("Unknown channel: " + channel);
		byte[] channelKey = chan.getKey();
		if (channelKey == null)
			throw new IllegalArgumentException("Not in channel: " + channel);
		Communique c = MessageType.CHANNEL_MESSAGE.create(this.me.getUsername());
		c.add(channel).add(Datatype.BINARY_BLOB, Encoding.Aes, data);
		c.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey).set(MetaSpace.AES_KEY, channelKey);
		this.server.send(c.sign());
	}

	public void sendUserMessage(String username, byte[] data)
	{
		UserData user = this.connectedUsers.get(username);
		if (user == null)
			throw new IllegalArgumentException("Unknown user: " + username);
		Communique c = MessageType.CLIENT_MESSAGE.create(this.me.getUsername());
		c.add(username).add(Datatype.BINARY_BLOB, Encoding.RsaEncrypt, data);
		c.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey).set(MetaSpace.RSA_EXTERN, user.getPublicKey());
		this.server.send(c.sign());
	}

	public CommClient createChannel(String channelName)
	{
		if (this.activeChannels.containsKey(channelName))
			throw new IllegalArgumentException("Channel already exists.");

		Communique msg = MessageType.CHANNEL_CREATE_REQUEST.create(this.me.getUsername());
		msg.add(channelName).getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
		this.server.send(msg.sign());
		Channel channel = new Channel(channelName);
		channel.setKey(AesUtil.randomKey());
		this.activeChannels.put(channelName, channel);
		return this;
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
