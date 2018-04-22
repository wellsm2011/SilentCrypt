package silentcrypt.core;

import java.net.InetAddress;
import java.net.InetSocketAddress;
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

import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.MetaSpace;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.comm.incoming.Filter;
import silentcrypt.comm.server.Host;
import silentcrypt.comm.server.ServerConn;
import silentcrypt.util.RsaKeyPair;
import silentcrypt.util.RsaUtil;
import silentcrypt.util.U;

/**
 * Contains factories and constructors for the certificate authority (CA) and clients thereof. Two types of requests are
 * allowed by this class: a public key distribution request, which allows clients to request the public RSA key from the
 * CA; and a certification request, which allows clients to request the CA to certify their public key.
 * <p>
 * This class will generate Communiques which may be modified to provide additional authentication information. The host
 * may call {@link CertAuthHost#requireCertVerification(Predicate)} and
 * {@link CertAuthHost#requireDistVerification(Predicate)} to test for the presence and validity of such information,
 * and the client may call {@link CertAuthClient#addCertificationAuthentication(Consumer)} and
 * {@link CertAuthClient#addDistributionAuthetication(Consumer)} to provide such information.
 * <p>
 * Public Key Distribution Request:<br>
 * Field 1: distribution request identifier.<br>
 * Field 2+: custom authentication information.
 * <p>
 * Certification Request: <br>
 * Field 1: certification request identifier.<br>
 * Field 2: RSA key to certify, encoded according to {@link RsaUtil#toBytes(RSAKeyParameters)}.<br>
 * Field 3+: custom authentication information.
 *
 * @see CertAuthHost
 * @see CertAuthClient
 * @author Michael Wells
 */
public class CertAuthComm
{
	/**
	 * The default port that clients and hosts will use to communicate unless another port is given.
	 */
	public static final int DEFAULT_PORT = 7778;

	private static final String	CERT_COMM_VERSION	= "SC-CERT-0001";
	private static final String	DIST_COMM_VERSION	= "SC-DIST-0001";

	private static final String	MESSAGE_REJECT	= "SC-CA-REJECT";
	private static final String	MESSAGE_ACCEPT	= "SC-CA-ACCEPT";

	/**
	 * Returns a new client which is ready to connect to the given address over the {@link #DEFAULT_PORT}.
	 *
	 * @param addr
	 * @return
	 */
	public static CertAuthClient client(InetAddress addr)
	{
		return new CertAuthClient(addr);
	}

	/**
	 * Returns a new client which is ready to connect to the given address over the given port.
	 *
	 * @param addr
	 * @return
	 */
	public static CertAuthClient client(InetSocketAddress addr) throws TimeoutException
	{
		return new CertAuthClient(addr);
	}

	/**
	 * Returns a new host which is ready to listen to the {@link #DEFAULT_PORT}.
	 *
	 * @param addr
	 * @return
	 */
	public static CertAuthHost host(RsaKeyPair key)
	{
		return new CertAuthHost(key);
	}

	/**
	 * Returns a new host which is ready to listen to the given port.
	 *
	 * @param addr
	 * @return
	 */
	public static CertAuthHost host(RsaKeyPair key, int port)
	{
		return new CertAuthHost(key).setPort(port);
	}

	public static class CertAuthHost
	{
		private static Communique MESSAGE_REJECT = new Communique().add(CertAuthComm.MESSAGE_REJECT);

		MetaSpace				key			= new MetaSpace();
		Predicate<Communique>	isDistReq	= c -> c.fieldCount() > 0 && Objects.equals(c.getField(0).quietData(String.class), CertAuthComm.DIST_COMM_VERSION);
		Predicate<Communique>	isCertReq	= c -> c.fieldCount() > 1 && Objects.equals(c.getField(0).quietData(String.class), CertAuthComm.CERT_COMM_VERSION);
		Predicate<Communique>	distFilter	= c -> true;
		Predicate<Communique>	certFilter	= c -> true;
		boolean					started		= false;
		boolean					isDaemon	= true;
		int						port		= DEFAULT_PORT;

		private CertAuthHost(RsaKeyPair key)
		{
			this.key.set(MetaSpace.RSA_SELF, key);
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
			Communique publicReply = new Communique().add(MESSAGE_ACCEPT).add(RsaUtil.toBytes(this.key.get(MetaSpace.RSA_SELF).getPublicRsa()));

			this.started = true;
			// Reply to distribution requests with the public reply iff they pass the distFilter.
			Host.start(this.port, this.isDaemon).setRejectionHandler((c, cons) -> cons.accept(MESSAGE_REJECT))
					.listen(Filter.by(c -> this.isDistReq.and(this.distFilter).test(c)), (c, cons) -> cons.accept(publicReply))
					.listen(Filter.by(c -> this.isCertReq.and(this.certFilter).test(c)), this::processCertificationRequest);
			return this;
		}

		private void processCertificationRequest(Communique communique, Consumer<Communique> client)
		{
			RSAKeyParameters orig = communique.getFields().get(1).data(RSAKeyParameters.class);
			byte[] origMod = orig.getModulus().toByteArray();
			byte[] origExp = orig.getExponent().toByteArray();

			ByteBuffer toEncrypt = ByteBuffer.allocate(origMod.length + origExp.length);
			toEncrypt.put(origMod).put(origExp);

			// Construct our reply.
			try
			{
				client.accept(new Communique().setMetaSpace(this.key).add(MESSAGE_ACCEPT).add(toEncrypt.array()).sign());
			} catch (IllegalStateException e)
			{
				U.e("Failed to fulfill certification request.", e);
				client.accept(MESSAGE_REJECT);
			}
		}
	}

	public static class CertAuthClient
	{
		InetSocketAddress		host;
		int						timeout		= 1 * 1000;
		Consumer<Communique>	distAuth	= U.emptyConsumer();
		Consumer<Communique>	certAuth	= U.emptyConsumer();

		private CertAuthClient(InetAddress addr)
		{
			this.host = new InetSocketAddress(addr, DEFAULT_PORT);
		}

		private CertAuthClient(InetSocketAddress addr)
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
		public byte[] certify(RSAKeyParameters key) throws TimeoutException, MessageRejectedException
		{
			Thread me = Thread.currentThread();
			AtomicBoolean isWaiting = new AtomicBoolean(true);

			Communique message = new Communique().add(CERT_COMM_VERSION).add(key);
			AtomicReference<byte[]> ref = new AtomicReference<>();

			send(message, (c, cons) -> {
				// Check to see if our request was accepted.
				if (c.fieldCount() >= 2 && c.getField(0).data(String.class).equals(MESSAGE_ACCEPT))
					ref.set(c.getField(1).data(byte[].class));
				// Wake the sleeping parent thread.
				if (isWaiting.getAndSet(false))
					me.interrupt();
			});

			try
			{
				Thread.sleep(this.timeout);
				isWaiting.set(false);
			} catch (InterruptedException e)
			{
				// Message received! Let's see if our request was accepted...
				if (Objects.isNull(ref.get()))
					throw new MessageRejectedException();
			}

			if (Objects.isNull(ref.get()))
				throw new TimeoutException("No response from " + this.host);

			return ref.get();
		}

		/**
		 * Makes a request to the server to certify the given key.
		 *
		 * @param key
		 * @param listener
		 * @return
		 */
		public CertAuthClient certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener)
		{
			this.certifyAsync(key, listener, ex -> {
				U.e("Error with certification request.", ex);
			});
			return this;
		}

		/**
		 * Makes a request to the server to certify the given key.
		 *
		 * @param key
		 * @param listener
		 * @param exceptionHandler
		 * @return
		 */
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

		/**
		 * Makes a request to the server to distribute its public key to us.
		 *
		 * @return
		 * @throws TimeoutException
		 */
		public RSAKeyParameters query() throws TimeoutException
		{
			Thread me = Thread.currentThread();
			AtomicBoolean isWaiting = new AtomicBoolean(true);

			Communique message = new Communique().add(DIST_COMM_VERSION);
			AtomicReference<RSAKeyParameters> ref = new AtomicReference<>();

			send(message, (c, cons) -> {
				// Check to see if our request was accepted.
				if (c.fieldCount() >= 2 && c.getField(0).data(String.class).equals(MESSAGE_ACCEPT))
					ref.set(RsaUtil.fromBytes(c.getField(1).data(byte[].class)));
				// Wake the sleeping parent thread.
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

		/**
		 * Makes a request to the server to distribute its public key to us.
		 *
		 * @param listener
		 * @return
		 */
		public CertAuthClient queryAsync(Consumer<RSAKeyParameters> listener)
		{
			this.queryAsync(listener, ex -> {
				U.e("Unable to query CA public key.", ex);
			});
			return this;
		}

		/**
		 * Makes a request to the server to distribute its public key to us.
		 *
		 * @param listener
		 * @param exceptionHandler
		 * @return
		 */
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

		public CertAuthClient setTimeout(int milliseconds)
		{
			this.timeout = milliseconds;
			return this;
		}

		private void send(Communique message, BiConsumer<Communique, Consumer<Communique>> handler)
		{
			ServerConn.get(this.host).listen(c -> true, handler).send(message);
		}
	}

	public static void main(String... strings) throws UnknownHostException, TimeoutException, MessageRejectedException, InterruptedException, InvalidCipherTextException
	{
		U.p("--- Starting Certification Authority Tests ---");
		U.p("Generating my RSA key...");
		RsaKeyPair myKey = RsaUtil.generateKeyPair();
		U.p("Generating the CA's RSA key...");
		RsaKeyPair caKey = RsaUtil.generateKeyPair();

		U.p("Starting CA...");
		// Start CA thread.
		CertAuthComm.host(caKey).start();

		InetAddress selfAddr = InetAddress.getByName("127.0.0.1");
		U.p("My public key: " + U.toString(myKey.getPublicRsa()));
		U.p("My private key: " + U.toString(myKey.getPrivateRsa()));

		CertAuthClient caConnection = CertAuthComm.client(selfAddr).setTimeout(10 * 1000);

		U.p("My certified public key: " + U.niceToString(caConnection.certify(myKey.getPublicRsa())));
		U.p("Server public key: " + U.toString(caConnection.query()));

		Communique signTest = Communique.of("Top Secret Message!");
		U.p("Signing a communique with my private key...");
		signTest.getMetaSpace().set(MetaSpace.RSA_SELF, myKey);
		signTest.sign();
		U.p("Verifying with my public key... (Should be valid)");
		U.p(signTest.validate(myKey.getPublicRsa()) ? "Validated!" : "Invalid signature!");
		U.p("Verifying with ca's public key... (Should be invalid)");
		U.p(signTest.validate(caKey.getPublicRsa()) ? "Validated!" : "Invalid signature!");
	}

}
