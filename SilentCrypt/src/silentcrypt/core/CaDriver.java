package silentcrypt.core;

import silentcrypt.core.CertAuthComm.CertAuthHost;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;

public class CaDriver
{
	public static void main(String... strings) throws InterruptedException
	{
		CertAuthHost host;
		RsaKeyPair myKey = RsaUtil.generateKeyPair();
		if (strings.length > 0)
			host = CertAuthComm.host(myKey, Integer.parseInt(strings[0]));
		else
			host = CertAuthComm.host(myKey);

		host.start();

		while (true)
			Thread.sleep(Long.MAX_VALUE);
	}
}
