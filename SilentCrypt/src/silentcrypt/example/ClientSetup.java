package silentcrypt.example;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeoutException;

import silentcrypt.core.CommClient;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;

public class ClientSetup
{
	private static CommClient serverConnection = null;

	public static void main(String... strings) throws IOException, TimeoutException
	{
		// The address of our Certificate Authority
		InetSocketAddress caAddr = new InetSocketAddress(InetAddress.getLocalHost(), 0);
		// The address of our Server
		InetSocketAddress srvAddr = new InetSocketAddress(InetAddress.getLocalHost(), 0);

		RsaKeyPair myKey = RsaUtil.generateKeyPair();
		String username = "Silent Crypt Test!";

		serverConnection = new CommClient(username, myKey, srvAddr, caAddr);
		serverConnection.listenToChannels(ClientSetup::processChannelMessage);
		serverConnection.listenToUsers(ClientSetup::processPrivateMessage);
		serverConnection.getChannels().forEach(c -> c.join(1000));
		if (!serverConnection.getChannels().stream().anyMatch(c -> c.getName().equals("TestChannel")))
			serverConnection.createChannel("TestChannel");
	}

	private static void processChannelMessage(String channel, byte[] data)
	{
		// Echo data back to the channel.
		serverConnection.sendChannelMessage(channel, data);
	}

	private static void processPrivateMessage(String user, byte[] data)
	{
		// Echo data back to the user.
		serverConnection.sendUserMessage(user, data);
	}
}
