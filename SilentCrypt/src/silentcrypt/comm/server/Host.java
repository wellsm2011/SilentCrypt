package silentcrypt.comm.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.incoming.CommuniqueListener;
import silentcrypt.comm.incoming.ConnectionMultiplexer;
import silentcrypt.util.U;

/**
 * Provides ease-of-use methods for accepting TCP connections which send and receive Communiques.
 *
 * @author Michael Wells
 * @author Andrew Binns
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
	 * @param isDaemon
	 * @return
	 */
	public static Host start(boolean isDaemon)
	{
		return start(AerisStd.PORT, isDaemon);
	}

	/**
	 * Start a new server host. Uses the given port.
	 *
	 * @param port
	 * @param isDaemon
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

	private ConnectionMultiplexer	multiplexer;
	private Consumer<Long>			closeHandler	= U.emptyConsumer();

	private Host(Supplier<ServerSocket> sockSrc, boolean isDaemon)
	{
		AtomicReference<Long> connectionId = new AtomicReference<>(1L);
		this.multiplexer = new ConnectionMultiplexer();
		this.src = sockSrc;
		init();

		Thread listener = new Thread(() -> {
			for (;;)
				try
				{
					long id = connectionId.getAndAccumulate(1L, (f, s) -> f + s);
					Socket t = this.sock.accept();
					U.p("Recieved opening connection from " + t.getRemoteSocketAddress());
					new Thread(() -> handle(t, id), "[Host] incoming connection handler : " + t.getRemoteSocketAddress()).start();
				} catch (IOException e)
				{
					U.e("Error accepting connection. " + e.getMessage());
				}
		}, "[Host] incoming connection manager");
		listener.setDaemon(isDaemon);

		U.p("Waiting for connections...");
		listener.start();
	}

	private void handle(Socket t, long connectionId)
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
		this.closeHandler.accept(connectionId);
		U.p("Connection from " + t.getRemoteSocketAddress() + " closed.");
	}

	public Host setCloseHandler(Consumer<Long> handler)
	{
		this.closeHandler = handler;
		return this;
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
