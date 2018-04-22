package silentcrypt.core;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;

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
	private UserData server = null;

	public CommClient(String username, RsaKeyPair myKey, InetAddress addr) throws TimeoutException, MessageRejectedException
	{
		super(username, myKey);
		ServerConn srv = ServerConn.get(new InetSocketAddress(addr, CommBase.DEFAULT_PORT));
		srv.listen(this::processMsg);
		this.server = new UserData("SC-SRV", null, Instant.now(), 0, srv::send);

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

	}

	private void processChannelJoinAuthentication(Communique msg)
	{

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
		this.server.replyTo(c);
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
		this.server.replyTo(c);
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
