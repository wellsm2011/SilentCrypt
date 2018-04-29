package silentcrypt.core;

import java.net.InetSocketAddress;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.MetaSpace;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.comm.server.Host;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.U;

public class CommServer extends CommBase
{
	Host server;

	public CommServer(RsaKeyPair myKey, InetSocketAddress caAddr, int port) throws MessageRejectedException, TimeoutException
	{
		super("SC-SRV", myKey);

		if (port == 0)
			port = CommBase.DEFAULT_PORT;

		this.server = Host.start(port);

		registerWithCa(caAddr);

		listen(this::processAuthenticationRequest, MessageType.AUTHENTICATION_REQUEST);
		listen(this::processInformationRequest, MessageType.INFORMATION_REQUEST);
		listen(this::processChannelJoinRequest, MessageType.CHANNEL_JOIN_REQUEST);
		listen(this::processChannelCreateRequest, MessageType.CHANNEL_CREATE_REQUEST);
		listen(this::processChannelJoinAccept, MessageType.CHANNEL_JOIN_ACCEPT);
		listen(this::processChannelJoinReject, MessageType.CHANNEL_JOIN_REJECT);
		listen(this::processChannelMessage, MessageType.CHANNEL_MESSAGE);
		listen(this::processClientMessage, MessageType.CLIENT_MESSAGE);
	}

	private boolean isKnownUser(Communique msg, Consumer<Communique> reply)
	{
		UserData user = this.connectedUsers.get(msg.getField(0).data(String.class));
		if (user == null || user.getConnectionId() != msg.getConnectionId())
		{
			reply.accept(generateRejectMessage(msg, "Unknown user; client must authenticate."));
			return false;
		}
		user.setReplyTo(reply);
		return true;
	}

	private void processAuthenticationRequest(Communique msg, Consumer<Communique> reply)
	{
		String username = msg.getField(1).data(String.class);
		RSAKeyParameters publicKey = msg.getField(2).data(RSAKeyParameters.class);
		byte[] cert = msg.getField(3).data(byte[].class);

		Communique r = MessageType.AUTHENTICATION_RESPONSE.create(this.me.getUsername());
		r.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey).set(MetaSpace.RSA_EXTERN, publicKey);
		r.add(this.me.getPublicKey()).add(this.me.getCert());

		UserData user = this.connectedUsers.get(username);
		if (user != null)
		{
			if (U.keyEquals(user.getPublicKey(), publicKey))
			{
				user.setConnectionId(msg.getConnectionId());
				user.setReplyTo(reply);
				reply.accept(r);
				return;
			}
			reply.accept(generateRejectMessage(msg, "Username " + username + " already in use."));
			return;
		}

		try
		{
			user = new UserData(username, publicKey, msg.getTimestamp(), msg.getConnectionId(), reply);
			user.setCert(cert, this.caPublic);
			Communique announcement = MessageType.SERVER_JOIN_ANNOUNCEMENT.create(username);
			announcement.add(publicKey).add(cert).getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
			announcement.sign();

			// Tell everyone else about our new friend.
			this.connectedUsers.values().forEach(ud -> ud.replyTo(announcement));
			this.connectedUsers.put(username, user);
			reply.accept(r.sign());
		} catch (IllegalArgumentException ex)
		{
			reply.accept(generateRejectMessage(msg, "Invalid certificate."));
		}
	}

	private void processInformationRequest(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;

		String channelName = "";
		Communique r = MessageType.INFORMATION_RESPONSE.create(this.me.getUsername());
		r.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);

		if (msg.fieldCount() >= 2)
			channelName = msg.getField(2).data(String.class);

		if (channelName.isEmpty())
		{
			// Request channel list.
			this.activeChannels.keySet().stream().forEach(r::add);
		} else
		{
			Channel channel = this.activeChannels.get(channelName);
			if (channel == null)
			{
				reply.accept(generateRejectMessage(msg, "Unknown channel: " + channelName));
				return;
			}
			channel.users.keySet().stream().forEach(r::add);
		}
		reply.accept(r.sign());
	}

	private void processChannelJoinRequest(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;

		String channelName = msg.getField(2).data(String.class);
		Channel channel = this.activeChannels.get(channelName);
		if (channel == null)
		{
			reply.accept(generateRejectMessage(msg, "Channel does not exist."));
			return;
		}
		try
		{
			// Forward message to someone in the channel.
			msg.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
			channel.users.values().stream().findFirst().get().replyTo(msg.sign());
		} catch (NoSuchElementException ex)
		{
			// We should never be here... this is bad.
			this.activeChannels.remove(channelName);
			reply.accept(generateRejectMessage(msg, "Channel does not exist."));
		}
	}

	private void processChannelCreateRequest(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;
		UserData user = this.connectedUsers.get(msg.getField(0).data(String.class));
		String channelName = msg.getField(2).data(String.class);

		if (this.activeChannels.containsKey(channelName))
		{
			reply.accept(generateRejectMessage(msg, "Channel already exists."));
			return;
		}

		Channel channel = new Channel(channelName);
		channel.users.put(user.getUsername(), user);

		Communique announcement = MessageType.CHANNEL_CREATION_ANNOUNCEMENT.create(this.me.getUsername());
		announcement.add(channelName).add(user.getUsername()).getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
		announcement.sign();
		this.connectedUsers.values().forEach(ud -> ud.replyTo(announcement));
	}

	private void processChannelJoinAccept(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;

	}

	private void processChannelJoinReject(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;

	}

	private void processChannelMessage(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;

		UserData user = this.connectedUsers.get(msg.getField(0).data(String.class));
		Channel channel = this.activeChannels.get(msg.getField(3).data(String.class));
		if (channel == null)
		{
			reply.accept(generateRejectMessage(msg, "Channel does not exist"));
			return;
		}
		if (!channel.users.containsKey(user.getUsername()))
		{
			reply.accept(generateRejectMessage(msg, "Client is not in channel"));
			return;
		}

		msg.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
		msg.sign();
		channel.users.values().forEach(ud -> {
			// Forward to the channel.
			if (!Objects.equals(user.getUsername(), ud.getUsername()))
				ud.replyTo(msg);
		});
	}

	private void processClientMessage(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg, reply))
			return;

		UserData target = this.connectedUsers.get(msg.getField(3).data(String.class));

		if (target == null)
		{
			reply.accept(generateRejectMessage(msg, "Unknown target."));
			return;
		}

		msg.getMetaSpace().set(MetaSpace.RSA_SELF, this.myKey);
		msg.sign();
		target.replyTo(msg);
	}
}
