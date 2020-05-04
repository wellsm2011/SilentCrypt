package silentcrypt.example;

import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.Datatype;
import silentcrypt.core.CertAuthComm;
import silentcrypt.core.CertAuthComm.CertAuthHost;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;

public class CaSetup
{
	public static void main(String... strings) throws InterruptedException
	{
		RsaKeyPair myKey = RsaUtil.generateKeyPair();
		// Start server and provide our verification requirements
		CertAuthHost host = CertAuthComm.host(myKey).requireCertVerification(CaSetup::verifyCertReq).start();
		while (host.isAlive())
			Thread.sleep(1000);
	}

	private static boolean verifyCertReq(Communique msg)
	{
		// Require an additional field which contains "Hello World" in it.
		if (msg.fieldCount() < 3)
			return false;
		if (msg.getField(2).getDatatype() != Datatype.STRING)
			return false;
		// Certificate authority will not authenticate unless this returns true.
		return msg.getField(2).data(String.class).equals("Hello World");
	}
}
