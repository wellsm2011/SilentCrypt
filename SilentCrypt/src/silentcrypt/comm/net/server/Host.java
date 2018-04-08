package silentcrypt.comm.net.server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import silentcrypt.comm.net.communique.Communique;
import silentcrypt.comm.net.incoming.CommuniqueListener;
import silentcrypt.comm.net.incoming.ConnectionMultiplexer;
import silentcrypt.util.U;

/**
 * Provides ease-of-use methods for accepting TCP connections which send and receive Communiques.
 *
 * @author Michael
 * @author Andrew
 */
public class Host implements Listenable<Host>
{
	/**
	 * Starts a new server host in a daemon thread. Uses the standard AERIS port.
	 *
	 * @return a new Host
	 */
	public static Host start()
	{
		return start(AerisStd.PORT, true);
	}

	/**
	 * Start a new server host in a daemon thread. Uses the given port.
	 *
	 * @param port
	 * @return a new Host
	 */
	public static Host start(int port)
	{
		return start(port, true);
	}

	/**
	 * Start a new server host. Uses the standard AERIS port.
	 *
	 * @return
	 */
	public static Host start(boolean isDaemon)
	{
		return start(AerisStd.PORT, isDaemon);
	}

	/**
	 * Start a new server host. Uses the given port.
	 *
	 * @return
	 */
	public static Host start(int port, boolean isDaemon)
	{
		return new Host(() -> {
			try
			{
				return new ServerSocket(port);
			} catch (IOException e)
			{
				U.e("Unable to bind to " + port + " " + e.getMessage());
				return null;
			}
		}, isDaemon);
	}

	private Supplier<ServerSocket>	src;
	private ServerSocket			sock;

	private ConnectionMultiplexer multiplexer;

	private Host(Supplier<ServerSocket> sockSrc, boolean isDaemon)
	{
		AtomicReference<BigInteger> connectionId = new AtomicReference<>(BigInteger.ONE);
		this.multiplexer = new ConnectionMultiplexer();
		this.src = sockSrc;
		init();

		U.p("Waiting for connections...");
		Thread listener = new Thread(() -> {
			for (;;)
				try
				{
					BigInteger id = connectionId.getAndAccumulate(BigInteger.ONE, (f, s) -> f.add(s));
					Socket t = this.sock.accept();
					U.p("Recieved opening connection from " + t.getRemoteSocketAddress());
					new Thread(() -> handle(t, id), "[Host] incoming connection handler : " + t.getRemoteSocketAddress()).start();
				} catch (IOException e)
				{
					U.e("Error accepting connection. " + e.getMessage());
				}
		}, "[Host] incoming connection manager");
		listener.setDaemon(isDaemon);
		listener.start();
	}

	private void handle(Socket t, BigInteger connectionId)
	{
		try
		{
			Supplier<Communique> src = Communique.from(t.getInputStream());
			Communique c = src.get();
			while (c != null)
			{
				c.setConnectionId(connectionId);
				this.multiplexer.distribute(c, comm -> {
					try
					{
						comm.write(t.getOutputStream());
					} catch (IOException e)
					{
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				});
				c = src.get();
			}
		} catch (IOException e)
		{
			U.e("No more data?....", e);
		}
		U.p("Connection from " + t.getRemoteSocketAddress() + " closed.");
	}

	private void init()
	{
		this.sock = this.src.get();
		while (this.sock == null)
		{
			U.e("Unable to instantiate.");
			U.sleep(AerisStd.RETRY_PERIOD);
			this.sock = this.src.get();
			if (this.sock != null)
				U.e("Finally able! Listening on " + AerisStd.PORT);
		}
	}

	/**
	 * Sets a handler for Communiques which are not processed by any other handlers.
	 *
	 * @param handler
	 * @return this object
	 */
	public Host setRejectionHandler(BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this.multiplexer.setRejectionHandler(handler);
		return this;
	}

	@Override
	public Host listen(CommuniqueListener listener)
	{
		this.multiplexer.listen(listener);
		return this;
	}
}
