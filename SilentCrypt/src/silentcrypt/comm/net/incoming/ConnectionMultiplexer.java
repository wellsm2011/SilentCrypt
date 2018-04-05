package silentcrypt.comm.net.incoming;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import silentcrypt.comm.net.communique.Communique;

/**
 * A class for managing a set of listeners which receive new Communiques and distributing messages to them.
 *
 * @author Andrew
 * @author Michael
 */
public class ConnectionMultiplexer
{
	private List<CommuniqueListener> handlers;

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

	private void _listen(Predicate<Communique> filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this.handlers.add(new CommuniqueListener(filter, handler));
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
		this.handlers.forEach(e -> {
			if (e.test(incoming))
				new Thread(() -> e.accept(incoming, reply), "Communique Distribution Handoff").start();
		});
		return this;
	}

	/**
	 * Register a new handler for incoming messages.
	 *
	 * @param filter
	 * @param handler
	 */
	public void listen(Filter filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		_listen(filter, handler);
	}

	/**
	 * Register a new handler for incoming messages.
	 *
	 * @param filter
	 * @param handler
	 */
	public void listen(Predicate<Communique> filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		_listen(filter, handler);
	}

	/**
	 * Register a new handler for incoming messages.
	 *
	 * @param filter
	 * @param handler
	 */
	public void listen(CommuniqueListener listener)
	{
		this.handlers.add(listener);
	}
}
