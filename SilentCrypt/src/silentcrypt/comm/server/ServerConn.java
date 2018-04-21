package silentcrypt.comm.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.incoming.CommuniqueListener;
import silentcrypt.comm.incoming.ConnectionMultiplexer;
import silentcrypt.util.U;

/**
 * Provides ease-of-use methods for sending and receiving Communiques over a TCP connection.
 *
 * @author Andrew Binns
 * @author Michael Wells
 */
public class ServerConn implements Listenable<ServerConn>
{
	public static ServerConn find()
	{
		try
		{
			// TODO have this do challenge-response with udp-broadcast
			InetAddress addr = InetAddress.getByName("aeris-prime");
			// TODO have port determined from challenge-response
			return new ServerConn(new InetSocketAddress(addr, AerisStd.PORT));
		} catch (UnknownHostException e)
		{
			U.e("Unable to locate primary AERIS instance.", e);
			return null;
		}

	}

	/**
	 * Creates a new server connection from the given InetAddress and Port.
	 *
	 * @param addr
	 * @param port
	 * @return
	 */
	public static ServerConn get(InetSocketAddress addr)
	{
		return new ServerConn(addr);
	}

	private InetSocketAddress					serverAddr;
	private Socket								sock		= null;
	private ConcurrentLinkedQueue<Communique>	sendQueue	= new ConcurrentLinkedQueue<>();
	private boolean								openConn	= false;

	private List<CommuniqueListener> handlers = new ArrayList<>();

	protected ServerConn(InetSocketAddress addr)
	{
		this.serverAddr = addr;
		openConn();
		startWatchDog();
		startSender();
	}

	private Communique buildRegistrationPacket(String serviceID)
	{
		Communique comm = new Communique();
		comm.add(AerisStd.SERVICE_REGISTRATION.getId());
		try
		{
			comm.add(InetAddress.getLocalHost().getHostName());
		} catch (UnknownHostException e)
		{
			comm.add("");
			U.e("Unable to determine host ident of current platform. ", e);
		}
		comm.add(serviceID);
		return comm;
	}

	@Override
	public ServerConn listen(CommuniqueListener listener)
	{
		this.handlers.add(listener);
		return this;
	}

	protected void openConn()
	{
		try
		{
			this.openConn = true;
			this.sock = new Socket(this.serverAddr.getAddress(), this.serverAddr.getPort());
			new ConnectionMultiplexer(this.sock.getInputStream(), this.sock.getOutputStream(), () -> this.handlers);
			U.p("Server Connection Open");
		} catch (IOException e)
		{
			this.sock = null;
			U.e("Unable to establish connection with host " + this.serverAddr + ": " + e.getMessage());
		}
	}

	/**
	 * Registers a new service for use over this connection.
	 *
	 * @param serviceID
	 * @return this object.
	 */
	public ServerConn register(String serviceID)
	{
		send(buildRegistrationPacket(serviceID));
		return this;
	}

	/**
	 * Sends the provided message to the server on the other end of this connection.
	 *
	 * @param comm
	 * @return this object.
	 */
	public ServerConn send(Communique comm)
	{
		this.sendQueue.add(comm);
		return this;
	}

	private void startSender()
	{
		Thread sender = new Thread(() -> {
			while (true)
			{
				if (this.sock != null)
				{
					if (!this.openConn)
					{
						try
						{
							this.sock.close();
						} catch (IOException e)
						{
						}
						this.sock = null;
					}
					while (!this.sendQueue.isEmpty())
					{
						try
						{
							Communique comm = this.sendQueue.peek();
							comm.write(this.sock.getOutputStream());
							this.sock.getOutputStream().flush();
							this.sendQueue.poll();
						} catch (IOException e)
						{
							U.e("Unable to send communique to server.", e);
							this.sock = null;
						}
					}
				}
			}
		}, "Communique Sender #" + hashCode());
		sender.setDaemon(true);
		sender.start();
	}

	public ServerConn closeConn()
	{
		this.openConn = false;
		return this;
	}

	private void startWatchDog()
	{
		byte[] msg = Communique.of(AerisStd.KEEP_ALIVE.getId()).bytes();
		Thread watcher = new Thread(() -> {
			U.sleep(AerisStd.HEARTBEAT_PERIOD);
			for (;;)
				try
				{
					this.sock.getOutputStream().write(msg);
					U.sleep(AerisStd.HEARTBEAT_PERIOD);
				} catch (NullPointerException e)
				{
					U.sleep(AerisStd.RETRY_PERIOD);
					if (this.openConn)
						openConn();
				} catch (Throwable t)
				{
					U.e("Unable to connect to server, retrying...", t);
					U.sleep(AerisStd.RETRY_PERIOD);
					if (this.openConn)
						openConn();
				}
		}, "Server Connection Watchdog #" + hashCode());
		watcher.setDaemon(true);
		watcher.setPriority(Thread.MIN_PRIORITY);
		watcher.start();
	}
}
