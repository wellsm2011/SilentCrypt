package silentcrypt.core;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeoutException;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.comm.server.Host;
import silentcrypt.util.RsaKeyPair;

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

	public void processAuthenticationRequest(Communique msg)
	{

	}

	public void processInformationRequest(Communique msg)
	{

	}

	public void processChannelJoinRequest(Communique msg)
	{

	}

	public void processChannelCreateRequest(Communique msg)
	{

	}

	public void processChannelJoinAccept(Communique msg)
	{

	}

	public void processChannelJoinReject(Communique msg)
	{

	}

	public void processChannelMessage(Communique msg)
	{

	}

	public void processClientMessage(Communique msg)
	{

	}
}
