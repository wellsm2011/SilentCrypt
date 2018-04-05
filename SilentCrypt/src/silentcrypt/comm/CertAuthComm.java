package silentcrypt.comm;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.net.communique.Communique;
import silentcrypt.comm.net.incoming.Filter;
import silentcrypt.comm.net.server.Host;
import silentcrypt.comm.net.server.ServerConn;
import silentcrypt.util.BinaryData;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

public class CertAuthComm
{
	public static class CertAuthHost
	{
		RsaKeyPair				key;
		Predicate<Communique>	isDistReq	= c -> c.fieldCount() > 0 && c.getFields().get(0).dataEquals(CertAuthComm.DIST_COMM_VERSION);
		Predicate<Communique>	isCertReq	= c -> c.fieldCount() > 1 && c.getFields().get(0).dataEquals(CertAuthComm.CERT_COMM_VERSION);
		Predicate<Communique>	pubFilter	= c -> true;
		Predicate<Communique>	certFilter	= c -> true;
		int						port		= 777;

		private CertAuthHost(RsaKeyPair key)
		{
			this.key = key;
		}

		/**
		 * Adds a new requirement on incoming certification Communiques. Communiques which do not pass the given filter
		 * are responded to with a failure code.
		 *
		 * @param filter
		 * @return
		 */
		public CertAuthHost requireCertVerification(Predicate<Communique> filter)
		{
			this.certFilter = this.certFilter.and(filter);
			return this;
		}

		public CertAuthHost requireDistVerification(Predicate<Communique> filter)
		{
			this.pubFilter = this.pubFilter.and(filter);
			return this;
		}

		public CertAuthHost setPort(int port)
		{
			this.port = port;
			return this;
		}

		public CertAuthHost start()
		{
			Communique publicReply = new Communique();
			publicReply.add(RsaUtil.toBytes(this.key.getPublicRsa()));
			U.p("Listening for connections.");
			Host.start(this.port).listen(Filter.by(this.isDistReq.or(this.isCertReq)), (c, cons) -> {
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
						reply.add(RsaUtil.encrypt(BinaryData.fromBytes(toEncrypt.array()), this.key.getPrivateRsa()).getBytes());
					} catch (InvalidCipherTextException e)
					{
						// TODO Handle unexpected RSA error.
						U.e("CA is unable to authenticate RSA key.", e);
					}
				cons.accept(reply);
			});
			return this;
		}
	}

	private static final byte[]	CERT_COMM_VERSION	= U.toBytes("SC-CERT-0001");
	private static final byte[]	DIST_COMM_VERSION	= U.toBytes("SC-DIST-0001");

	private static final String MESSAGE_REJECT = "SC-CA-REJECT";

	public static CertAuthComm client(InetAddress addr)
	{
		return new CertAuthComm(addr);
	}

	public static RSAKeyParameters getCaPublicKey(InetAddress addr, int port) throws TimeoutException
	{
		return CertAuthComm.getCaPublicKey(addr, port, 60 * 1000);
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

	public static CertAuthHost host(RsaKeyPair key)
	{
		return new CertAuthHost(key);
	}

	int port = 777;

	InetAddress host;

	int timeout = 1 * 1000;

	private CertAuthComm(InetAddress addr)
	{
		this.host = addr;
	}

	public byte[] certify(RSAKeyParameters key) throws TimeoutException
	{
		Thread me = Thread.currentThread();
		AtomicBoolean isWaiting = new AtomicBoolean(true);

		Communique message = new Communique();
		message.add(RsaUtil.toBytes(key));
		AtomicReference<byte[]> ref = new AtomicReference<>();

		this.send(message, c -> c.getFields().size() == 1, (c, cons) -> {
			ref.set(c.getFields().get(0).dataArray());
			if (isWaiting.getAndSet(false))
				me.interrupt();
		});

		try
		{
			Thread.sleep(this.timeout);
			isWaiting.set(false);
		} catch (InterruptedException e)
		{
			// Do nothing. We got our message!
		}

		if (Objects.isNull(ref.get()))
			throw new TimeoutException("No response from " + this.host);

		return ref.get();
	}

	public void certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener)
	{
		this.certifyAsync(key, listener, ex -> {
			throw new IllegalStateException(ex);
		});
	}

	public void certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener, Consumer<Exception> exceptionHandler)
	{
		Thread thread = new Thread(() -> {
			try
			{
				listener.accept(this.certify(key));
			} catch (Exception ex)
			{
				exceptionHandler.accept(ex);
			}
		});
		thread.setDaemon(true);
		thread.setName("Certification Watchdog #" + this.hashCode());
		thread.start();
	}

	public RSAKeyParameters query() throws TimeoutException
	{
		Thread me = Thread.currentThread();
		AtomicBoolean isWaiting = new AtomicBoolean(true);

		Communique message = new Communique();
		AtomicReference<RSAKeyParameters> ref = new AtomicReference<>();

		this.send(message, c -> c.getFields().size() == 1, (c, cons) -> {
			ref.set(RsaUtil.fromBytes(c.getFields().get(0).dataArray()));
			if (isWaiting.getAndSet(false))
				me.interrupt();
		});

		try
		{
			Thread.sleep(this.timeout);
			isWaiting.set(false);
		} catch (InterruptedException e)
		{
			// Do nothing. We got our message!
		}

		if (Objects.isNull(ref.get()))
			throw new TimeoutException("No response from " + this.host);

		return ref.get();
	}

	public void queryAsync(Consumer<RSAKeyParameters> listener)
	{
		this.queryAsync(listener, ex -> {
			U.e("Unable to query CA public key.", ex);
		});
	}

	public void queryAsync(Consumer<RSAKeyParameters> listener, Consumer<Exception> exceptionHandler)
	{
		Thread thread = new Thread(() -> {
			try
			{
				listener.accept(this.query());
			} catch (Exception ex)
			{
				exceptionHandler.accept(ex);
			}
		});
		thread.setDaemon(true);
		thread.setName("Certification Watchdog #" + this.hashCode());
		thread.start();
	}

	private void send(Communique message, Filter filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		ServerConn.get(this.host, this.port).listen(filter, handler).send(message);
	}

	public CertAuthComm setPort(int port)
	{
		this.port = port;
		return this;
	}

	public CertAuthComm setTimeout(int milliseconds)
	{
		this.timeout = milliseconds;
		return this;
	}
}
