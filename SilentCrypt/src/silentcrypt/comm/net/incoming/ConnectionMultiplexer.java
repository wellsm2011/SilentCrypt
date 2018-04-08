package silentcrypt.comm.net.incoming;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import silentcrypt.comm.net.communique.Communique;
import silentcrypt.comm.net.server.Listenable;

/**
 * A class for managing a set of listeners which receive new Communiques and distributing messages to them.
 *
 * @author Andrew Binns
 * @author Michael Wells
 */
public class ConnectionMultiplexer implements Listenable<ConnectionMultiplexer>
{
	private List<CommuniqueListener>						handlers;
	private BiConsumer<Communique, Consumer<Communique>>	rejectionHandler	= null;

	public ConnectionMultiplexer()
	{
		this(ArrayList::new);
	}

	public ConnectionMultiplexer(InputStream in, OutputStream output, Supplier<List<CommuniqueListener>> handlerSrc)
	{
		this(Communique.from(in), c -> {
			try
			{
				c.write(output);
			} catch (IOException e)
			{
				e.printStackTrace();
			}
		}, handlerSrc);
	}

	public ConnectionMultiplexer(Supplier<Communique> in, Consumer<Communique> output, Supplier<List<CommuniqueListener>> handlerSrc)
	{
		this(handlerSrc);
		Thread t = new Thread(() -> {
			Communique c;
			while ((c = in.get()) != null)
			{
				for (CommuniqueListener e : this.handlers)
				{
					if (e != null && c != null)
					{
						if (e.test(c))
						{
							Communique d = c;
							new Thread(() -> e.accept(d, output), "Communique Handoff").start();
						}
					}
				}
			}
		}, "Connection Multiplexer");
		t.setDaemon(true);
		t.start();
	}

	public ConnectionMultiplexer(Supplier<List<CommuniqueListener>> handlerSrc)
	{
		this.handlers = handlerSrc.get();
	}

	/**
	 * Sets a handler for Communiques which are not processed by any other handlers.
	 *
	 * @param handler
	 * @return
	 */
	public ConnectionMultiplexer setRejectionHandler(BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this.rejectionHandler = handler;
		return this;
	}

	/**
	 * Distributes the given Communique and reply in parallel among the registered handlers.
	 *
	 * @param incoming
	 * @param reply
	 * @return this object
	 */
	public ConnectionMultiplexer distribute(Communique incoming, Consumer<Communique> reply)
	{
		boolean handled = false;
		for (CommuniqueListener e : this.handlers)
		{
			if (e.test(incoming))
			{
				new Thread(() -> e.accept(incoming, reply), "Communique Distribution Handoff").start();
				handled = true;
			}
		}
		if (!handled && this.rejectionHandler != null)
			this.rejectionHandler.accept(incoming, reply);
		return this;
	}

	@Override
	public ConnectionMultiplexer listen(CommuniqueListener listener)
	{
		this.handlers.add(listener);
		return this;
	}
}
