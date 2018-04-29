package silentcrypt.core;

import java.net.InetSocketAddress;
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

	private boolean isKnownUser(Communique msg)
	{
		UserData user = this.connectedUsers.get(msg.getField(0).data(String.class));
		if (user == null || user.getConnectionId() != msg.getConnectionId())
		{
			rejectMessage(msg, "Unknown user; client must authenticate.");
			return false;
		}
		return true;
	}

	private void processAuthenticationRequest(Communique msg, Consumer<Communique> reply)
	{
		String username = msg.getField(1).data(String.class);
		RSAKeyParameters publicKey = msg.getField(2).data(RSAKeyParameters.class);

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
			rejectMessage(msg, "Username " + username + " already in use.");
			return;
		}

		user = new UserData(username, msg.getField(2).data(RSAKeyParameters.class), msg.getTimestamp(), msg.getConnectionId(), reply);
		this.connectedUsers.put(username, user);
		reply.accept(r.sign());
	}

	private void processInformationRequest(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
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
				rejectMessage(msg, "Unknown channel: " + channelName);
				return;
			}
			channel.users.keySet().stream().forEach(r::add);
		}
		reply.accept(r.sign());
	}

	private void processChannelJoinRequest(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
			return;

	}

	private void processChannelCreateRequest(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
			return;

	}

	private void processChannelJoinAccept(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
			return;

	}

	private void processChannelJoinReject(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
			return;

	}

	private void processChannelMessage(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
			return;

	}

	private void processClientMessage(Communique msg, Consumer<Communique> reply)
	{
		if (!isKnownUser(msg))
			return;

	}
}
