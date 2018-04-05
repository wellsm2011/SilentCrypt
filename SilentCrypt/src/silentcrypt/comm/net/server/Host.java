package silentcrypt.comm.net.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
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
	 * Starts a new server host. Uses standard port.
	 *
	 * @return a new Host
	 */
	public static Host start()
	{
		return Host.start(AerisStd.PORT);
	}

	/**
	 * Start a new server host. Uses the given port.
	 *
	 * @param port
	 * @return a new Host
	 */
	public static Host start(int port)
	{
		return new Host(() -> {
			try
			{
				return new ServerSocket(port);
			} catch (IOException e)
			{
				U.e("Unable to bind to " + AerisStd.PORT + " " + e.getMessage());
				return null;
			}
		});
	}

	private Supplier<ServerSocket>	src;
	private ServerSocket			sock;

	private ConnectionMultiplexer multiplexer;

	private Host(Supplier<ServerSocket> sockSrc)
	{
		this.multiplexer = new ConnectionMultiplexer();
		this.src = sockSrc;
		init();
		Thread listener = new Thread(() -> {
			for (;;)
				try
				{
					U.p("Waiting for connection...");
					Socket t = this.sock.accept();
					new Thread(() -> handle(t), "[Host] incoming connection handler : " + t.getRemoteSocketAddress()).start();
				} catch (IOException e)
				{
					U.e("Error accepting connection. " + e.getMessage());
				}
		}, "[Host] incoming connection manager");
		listener.setDaemon(true);
		listener.start();
	}

	private void handle(Socket t)
	{
		U.p("Recieved opening connection from " + t.getRemoteSocketAddress());
		try
		{
			Supplier<Communique> src = Communique.from(t.getInputStream());
			Communique c;
			while ((c = src.get()) != null)
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

	@Override
	public Host listen(CommuniqueListener listener)
	{
		this.multiplexer.listen(listener);
		return this;
	}
}
