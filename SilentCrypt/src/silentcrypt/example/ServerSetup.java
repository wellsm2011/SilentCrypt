package silentcrypt.example;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeoutException;

import silentcrypt.core.CommServer;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;

public class ServerSetup
{
	public static void main(String... strings) throws IOException, TimeoutException, InterruptedException
	{
		// Talk over local host using the CA default port.
		InetSocketAddress caAddr = new InetSocketAddress(InetAddress.getLocalHost(), 0);
		RsaKeyPair myKey = RsaUtil.generateKeyPair();

		// Start up a comm host over the default SC Server port.
		CommServer host = new CommServer(myKey, caAddr, 0);
		while (host.isAlive())
			Thread.sleep(1000);
	}
}
