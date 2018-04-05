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

import backend.stdcomm.communique.Communique;
import backend.stdcomm.incoming.Filter;
import backend.stdcomm.server.Host;
import backend.stdcomm.server.ServerConn;
import silentcrypt.core.util.BinaryData;
import silentcrypt.core.util.RsaKeyPair;
import silentcrypt.core.util.RsaUtil;
import silentcrypt.core.util.U;

public class CertAuthComm
{
	public static class CertAuthHost
	{
		RsaKeyPair				key;
		Predicate<Communique>	filter	= c -> true;
		int						port	= 777;

		private CertAuthHost(RsaKeyPair key)
		{
			this.key = key;
		}

		public CertAuthHost setPort(int port)
		{
			this.port = port;
			return this;
		}

		public CertAuthHost filter(Predicate<Communique> filter)
		{
			this.filter = this.filter.and(filter);
			return this;
		}

		public CertAuthHost start()
		{
			Communique publicReply = new Communique();
			publicReply.add(RsaUtil.toBytes(this.key.getPublicRsa()));
			U.p("Listening for connections.");
			Host.start(this.port).listen(Filter.by(this.filter), (c, cons) -> {
				Communique reply = publicReply;

				if (!c.getFields().isEmpty())
				{
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
						e.printStackTrace();
					}
				}

				U.p("Reply: " + reply);
				cons.accept(reply);
			});
			return this;
		}
	}

	int			port	= 777;
	InetAddress	host;
	int			timeout	= 1 * 1000;

	public static CertAuthComm client(InetAddress addr)
	{
		return new CertAuthComm(addr);
	}

	public static CertAuthHost host(RsaKeyPair key)
	{
		return new CertAuthHost(key);
	}

	private CertAuthComm(InetAddress addr)
	{
		this.host = addr;
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

	private void send(Communique message, Filter filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		ServerConn.get(this.host, this.port).listen(filter, handler).send(message);
	}

	public RSAKeyParameters query() throws TimeoutException
	{
		Thread me = Thread.currentThread();
		AtomicBoolean isWaiting = new AtomicBoolean(true);

		Communique message = new Communique();
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

	public void queryAsync(Consumer<RSAKeyParameters> listener)
	{
		queryAsync(listener, ex -> {
			throw new IllegalStateException(ex);
		});
	}

	public void queryAsync(Consumer<RSAKeyParameters> listener, Consumer<Exception> exceptionHandler)
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
	}

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

	public void certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener)
	{
		certifyAsync(key, listener, ex -> {
			throw new IllegalStateException(ex);
		});
	}

	public void certifyAsync(RSAKeyParameters key, Consumer<byte[]> listener, Consumer<Exception> exceptionHandler)
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
	}

	public static RSAKeyParameters getCaPublicKey(InetAddress addr, int port) throws TimeoutException
	{
		return getCaPublicKey(addr, port, 60 * 1000);
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
}
