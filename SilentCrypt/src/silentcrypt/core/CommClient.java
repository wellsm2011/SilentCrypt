package silentcrypt.core;

import java.util.concurrent.TimeoutException;

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

	}

	public void sendUserMessage(String username, byte[] data)
	{

	}
}
