package silentcrypt.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.net.communique.Communique;
import silentcrypt.comm.net.server.Host;
import silentcrypt.comm.net.server.ServerConn;
import silentcrypt.util.BinaryData;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

public class ScCa
{
	public static final int CA_PORT = 776;

	public static byte[] certifyCertificate(RSAKeyParameters key, InetAddress addr, int port, int timeoutMilis) throws TimeoutException
	{
		Thread me = Thread.currentThread();
		AtomicBoolean isWaiting = new AtomicBoolean(true);

		Communique message = new Communique();
		message.add(RsaUtil.toBytes(key));
		AtomicReference<byte[]> ref = new AtomicReference<>();

		ServerConn.get(addr, port).listen(c -> c.getFields().size() == 1, (c, cons) -> {
			ref.set(c.getFields().get(0).dataArray());
			if (isWaiting.getAndSet(false))
				me.interrupt();
		}).send(message);

		try
		{
			Thread.sleep(timeoutMilis);
			isWaiting.set(false);
		} catch (InterruptedException e)
		{
			// Do nothing.
		}

		if (Objects.isNull(ref.get()))
			throw new TimeoutException("No response from " + addr);

		return ref.get();
	}

	public static void echoServer()
	{
		int portNumber = ScCa.CA_PORT;

		try (ServerSocket serverSocket = new ServerSocket(portNumber);
				Socket clientSocket = serverSocket.accept();
				PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));)
		{
			String inputLine;
			while ((inputLine = in.readLine()) != null)
				out.println(inputLine);
		} catch (IOException e)
		{
			System.out.println("Exception caught when trying to listen on port " + portNumber + " or listening for a connection");
			System.out.println(e.getMessage());
		}
	}

	public static RSAKeyParameters getCaPublicKey(InetAddress addr, int port, int timeoutMilis) throws TimeoutException
	{
		Thread me = Thread.currentThread();
		AtomicBoolean isWaiting = new AtomicBoolean(true);

		Communique message = new Communique();
		AtomicReference<RSAKeyParameters> ref = new AtomicReference<>();

		ServerConn.get(addr, port).listen(c -> c.getFields().size() == 1, (c, cons) -> {
			ref.set(RsaUtil.fromBytes(c.getFields().get(0).dataArray()));
			if (isWaiting.getAndSet(false))
				me.interrupt();
		}).send(message);

		try
		{
			Thread.sleep(timeoutMilis);
			isWaiting.set(false);
		} catch (InterruptedException e)
		{
			// Do nothing.
		}

		if (Objects.isNull(ref.get()))
			throw new TimeoutException("No response from " + addr);

		return ref.get();
	}

	public static void main(String... strings) throws UnknownHostException, TimeoutException
	{

		RsaKeyPair key = RsaUtil.generateKeyPair();
		// new Thread(() -> echoServer()).start();

		ScCa.startCaThread(key);

		InetAddress selfAddr = InetAddress.getByName("127.0.0.1");
		U.p("My public key: " + U.toString(key.getPublicRsa()));
		U.p("My private key: " + U.toString(key.getPrivateRsa()));
		U.p("Server public key: " + U.toString(ScCa.getCaPublicKey(selfAddr, ScCa.CA_PORT, 60 * 1000)));
		U.p("My certified public key: " + U.niceToString(ScCa.certifyCertificate(key.getPublicRsa(), selfAddr, ScCa.CA_PORT, 60 * 1000)));

		// Keep the VM alive.
		while (true)
			;
	}

	public static void startCaThread(RsaKeyPair key)
	{
		Communique publicReply = new Communique();
		publicReply.add(RsaUtil.toBytes(key.getPublicRsa()));
		U.p("Listening for connections.");
		Host.start(ScCa.CA_PORT).listen(c -> c.getFields().size() < 2, (c, cons) -> {
			Communique reply = publicReply;

			if (!c.getFields().isEmpty())
				try
				{
					RSAKeyParameters orig = RsaUtil.fromBytes(c.getFields().get(0).dataArray());
					byte[] origMod = orig.getModulus().toByteArray();
					byte[] origExp = orig.getExponent().toByteArray();

					ByteBuffer toEncrypt = ByteBuffer.allocate(origMod.length + origExp.length);
					toEncrypt.put(origMod).put(origExp);

					reply = new Communique();
					reply.add(RsaUtil.encrypt(BinaryData.fromBytes(toEncrypt.array()), key.getPrivateRsa()).getBytes());
				} catch (InvalidCipherTextException e)
				{
					// TODO Handle unexpected RSA error.
					e.printStackTrace();
				}

			U.p("Reply: " + reply);
			cons.accept(reply);
		});
	}
}
