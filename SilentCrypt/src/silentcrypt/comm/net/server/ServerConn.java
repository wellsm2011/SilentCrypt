package silentcrypt.comm.net.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import silentcrypt.comm.net.communique.Communique;
import silentcrypt.comm.net.incoming.CommuniqueListener;
import silentcrypt.comm.net.incoming.ConnectionMultiplexer;
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
			return new ServerConn(addr, AerisStd.PORT);
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
	public static ServerConn get(InetAddress addr, int port)
	{
		return new ServerConn(addr, port);
	}

	private InetAddress							serverAddr;
	private Socket								sock;
	private int									serverPort;
	private ConcurrentLinkedQueue<Communique>	sendQueue	= new ConcurrentLinkedQueue<>();

	private List<CommuniqueListener> handlers = new ArrayList<>();

	protected ServerConn(InetAddress addr, int port)
	{
		this.serverAddr = addr;
		this.serverPort = port;
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
			this.sock = new Socket(this.serverAddr, this.serverPort);
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
				if (this.sock != null)
					while (!this.sendQueue.isEmpty())
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
		}, "Communique Sender #" + hashCode());
		sender.setDaemon(true);
		sender.start();
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
					openConn();
				} catch (Throwable t)
				{
					U.e("Unable to connect to server, retrying...", t);
					U.sleep(AerisStd.RETRY_PERIOD);
					openConn();
				}
		}, "Server Connection Watchdog #" + hashCode());
		watcher.setDaemon(true);
		watcher.setPriority(Thread.MIN_PRIORITY);
		watcher.start();
	}
}
