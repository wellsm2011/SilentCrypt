package silentcrypt.comm;

import java.net.InetAddress;
import java.net.UnknownHostException;
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
import silentcrypt.core.ScCa;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

/**
 * @author Michael
 */
public class CertAuthComm
{
	public static final int DEFAULT_PORT = 777;

	private static final String	CERT_COMM_VERSION	= "SC-CERT-0001";
	private static final String	DIST_COMM_VERSION	= "SC-DIST-0001";

	private static final String	MESSAGE_REJECT	= "SC-CA-REJECT";
	private static final String	MESSAGE_ACCEPT	= "SC-CA-ACCEPT";

	public static CertAuthClient client(InetAddress addr)
	{
		return new CertAuthClient(addr);
	}

	public static CertAuthClient client(InetAddress addr, int port) throws TimeoutException
	{
		return CertAuthComm.client(addr).setPort(port);
	}

	public static CertAuthHost host(RsaKeyPair key)
	{
		return new CertAuthHost(key);
	}

	public static CertAuthHost host(RsaKeyPair key, int port)
	{
		return new CertAuthHost(key).setPort(port);
	}

	public static class CertAuthHost
	{
		RsaKeyPair				key;
		Predicate<Communique>	isDistReq	= c -> c.fieldCount() > 0 && c.getFields().get(0).dataEquals(U.toBytes(CertAuthComm.DIST_COMM_VERSION));
		Predicate<Communique>	isCertReq	= c -> c.fieldCount() > 1 && c.getFields().get(0).dataEquals(U.toBytes(CertAuthComm.CERT_COMM_VERSION));
		Predicate<Communique>	distFilter	= c -> true;
		Predicate<Communique>	certFilter	= c -> true;
		boolean					started		= false;
		boolean					isDaemon	= true;
		int						port		= DEFAULT_PORT;

		private CertAuthHost(RsaKeyPair key)
		{
			this.key = key;
		}

		/**
		 * Adds a new requirement on incoming certification requests. Communiques which do not pass the given filter are
		 * responded to with a failure code.
		 *
		 * @param filter
		 * @return this object.
		 */
		public CertAuthHost requireCertVerification(Predicate<Communique> filter)
		{
			this.certFilter = this.certFilter.and(filter);
			return this;
		}

		/**
		 * Adds a new requirement on incoming CA public key distribution requests. Communiques which do not pass the
		 * given filter are responded to with a failure code.
		 *
		 * @param filter
		 * @return this object.
		 */
		public CertAuthHost requireDistVerification(Predicate<Communique> filter)
		{
			this.distFilter = this.distFilter.and(filter);
			return this;
		}

		/**
		 * Sets the port over which communication will carry out.
		 *
		 * @param port
		 * @return this object.
		 */
		public CertAuthHost setPort(int port)
		{
			if (this.started)
				throw new IllegalStateException("Server already started!");
			this.port = port;
			return this;
		}

		/**
		 * Sets whether the thread started by this CertAuthHost is a daemon thread or not. By default, all host threads
		 * are daemon threads.
		 *
		 * @param daemon
		 * @return
		 */
		public CertAuthHost setDaemon(boolean daemon)
		{
			if (this.started)
				throw new IllegalStateException("Server already started!");
			this.isDaemon = daemon;
			return this;
		}

		/**
		 * Starts listening for new communications.
		 *
		 * @return this object.
		 */
		public CertAuthHost start()
		{
			Communique publicReply = new Communique().add(MESSAGE_ACCEPT).add(RsaUtil.toBytes(this.key.getPublicRsa()));

			Communique messageReject = new Communique().add(MESSAGE_REJECT);

			this.started = true;
			// Reply to distribution requests with the public reply iff they pass the distFilter.
			Host.start(this.port, this.isDaemon).listen(Filter.by(c -> this.isDistReq.test(c)), (c, cons) -> cons.accept(this.distFilter.test(c) ? publicReply : messageReject))
					.listen(Filter.by(c -> this.isCertReq.test(c)), (c, cons) -> {
						if (!this.certFilter.test(c))
						{
							cons.accept(messageReject);
							return;
						}

						AtomicBoolean hasError = new AtomicBoolean(false);
						RSAKeyParameters orig = RsaUtil.fromBytes(c.getFields().get(0).dataArray());
						byte[] origMod = orig.getModulus().toByteArray();
						byte[] origExp = orig.getExponent().toByteArray();

						ByteBuffer toEncrypt = ByteBuffer.allocate(origMod.length + origExp.length);
						toEncrypt.put(origMod).put(origExp);

						Communique reply = new Communique().add(MESSAGE_ACCEPT).add(toEncrypt.array(), cf -> {
							try
							{
								cf.encrypt(this.key.getPrivateRsa());
							} catch (InvalidCipherTextException | IllegalStateException e)
							{
								// Well. We got a really weird error... That sucks. ABORT!
								hasError.set(true);
								U.e("Error processing CA response.", e);
							}
						});

						if (!hasError.get())
							cons.accept(reply);
						else
							cons.accept(messageReject);
					});
			return this;
		}
	}

	public static class CertAuthClient
	{
		InetAddress				host;
		int						port		= DEFAULT_PORT;
		int						timeout		= 1 * 1000;
		Consumer<Communique>	distAuth	= c -> {
											};
		Consumer<Communique>	certAuth	= c -> {
											};

		private CertAuthClient(InetAddress addr)
		{
			this.host = addr;
		}

		/**
		 * Adds a new certification authentication consumer to this client. Such consumers are given fully formed
		 * certification messages and are allowed to modify the messages before they are sent to a server.
		 *
		 * @param certAuth
		 * @return this object
		 */
		public CertAuthClient addCertificationAuthentication(Consumer<Communique> certAuth)
		{
			this.certAuth = this.certAuth.andThen(certAuth);
			return this;
		}

		/**
		 * Adds a new distribution authentication consumer to this client. Such consumers are given fully formed public
		 * CA key requests and are allowed to modify the messages before they are sent to a server.
		 *
		 * @param distAuth
		 * @return
		 */
		public CertAuthClient addDistributionAuthetication(Consumer<Communique> distAuth)
		{
			this.distAuth = this.distAuth.andThen(distAuth);
			return this;
		}

		/**
		 * Makes a request to the server to certify the given key.
		 *
		 * @param key
		 * @return A byte array which represents the given key when encrypted by the server.
		 * @throws TimeoutException
		 */
		public byte[] certify(RSAKeyParameters key) throws TimeoutException
		{
			Thread me = Thread.currentThread();
			AtomicBoolean isWaiting = new AtomicBoolean(true);

			Communique message = new Communique();
			message.add(RsaUtil.toBytes(key));
			AtomicReference<byte[]> ref = new AtomicReference<>();

			send(message, c -> c.getFields().size() == 1, (c, cons) -> {
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

		public CertAuthClient certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener)
		{
			this.certifyAsync(key, listener, ex -> {
				throw new IllegalStateException(ex);
			});
			return this;
		}

		public CertAuthClient certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener, Consumer<Exception> exceptionHandler)
		{
			Thread thread = new Thread(() -> {
				try
				{
					listener.accept(certify(key));
				} catch (Exception ex)
				{
					exceptionHandler.accept(ex);
				}
			});
			thread.setDaemon(true);
			thread.setName("Certification Watchdog #" + hashCode());
			thread.start();
			return this;
		}

		public RSAKeyParameters query() throws TimeoutException
		{
			Thread me = Thread.currentThread();
			AtomicBoolean isWaiting = new AtomicBoolean(true);

			Communique message = new Communique().add(DIST_COMM_VERSION);
			AtomicReference<RSAKeyParameters> ref = new AtomicReference<>();

			send(message, c -> c.getFields().size() == 1, (c, cons) -> {
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

		public CertAuthClient queryAsync(Consumer<RSAKeyParameters> listener)
		{
			this.queryAsync(listener, ex -> {
				U.e("Unable to query CA public key.", ex);
			});
			return this;
		}

		public CertAuthClient queryAsync(Consumer<RSAKeyParameters> listener, Consumer<Exception> exceptionHandler)
		{
			Thread thread = new Thread(() -> {
				try
				{
					listener.accept(query());
				} catch (Exception ex)
				{
					exceptionHandler.accept(ex);
				}
			});
			thread.setDaemon(true);
			thread.setName("Certification Watchdog #" + hashCode());
			thread.start();
			return this;
		}

		private void send(Communique message, Filter filter, BiConsumer<Communique, Consumer<Communique>> handler)
		{
			ServerConn.get(this.host, this.port).listen(filter, handler).send(message);
		}

		public CertAuthClient setPort(int port)
		{
			this.port = port;
			return this;
		}

		public CertAuthClient setTimeout(int milliseconds)
		{
			this.timeout = milliseconds;
			return this;
		}
	}

	public static void main(String... strings) throws UnknownHostException, TimeoutException
	{

		RsaKeyPair key = RsaUtil.generateKeyPair();
		// new Thread(() -> echoServer()).start();

		CertAuthHost host = CertAuthComm.host(key).start();

		InetAddress selfAddr = InetAddress.getByName("127.0.0.1");
		U.p("My public key: " + U.toString(key.getPublicRsa()));
		U.p("My private key: " + U.toString(key.getPrivateRsa()));
		U.p("Server public key: " + U.toString(ScCa.getCaPublicKey(selfAddr, ScCa.CA_PORT, 60 * 1000)));
		U.p("My certified public key: " + U.niceToString(ScCa.certifyCertificate(key.getPublicRsa(), selfAddr, ScCa.CA_PORT, 60 * 1000)));

		// Keep the VM alive.
		while (true)
			;
	}
}
