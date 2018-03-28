package backend.stdcomm.incoming;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import backend.stdcomm.communique.Communique;

public class ConnectionMultiplexer
{
	private List<Entry> handlers;

	public ConnectionMultiplexer()
	{
		this(ArrayList::new);
	}

	public ConnectionMultiplexer(InputStream in, OutputStream output, Supplier<List<Entry>> handlerSrc)
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

	public ConnectionMultiplexer(Supplier<Communique> in, Consumer<Communique> output, Supplier<List<Entry>> handlerSrc)
	{
		this(handlerSrc);
		Thread t = new Thread(() -> {
			Communique c;
			while ((c = in.get()) != null)
				for (Entry e : this.handlers)
					if (e != null && c != null)
						if (e.test(c))
						{
							Communique d = c;
							new Thread(() -> e.accept(d, output), "Communique Handoff").start();
						}
		}, "Connection Multiplexer");
		t.setDaemon(true);
		t.start();
	}

	public ConnectionMultiplexer(Supplier<List<Entry>> handlerSrc)
	{
		this.handlers = handlerSrc.get();
	}

	private <T extends Predicate<Communique>> void _listen(T filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this.handlers.add(new Entry(filter, handler));
	}

	public ConnectionMultiplexer distribute(Communique incoming, Consumer<Communique> reply)
	{
		this.handlers.forEach(e -> {
			if (e.test(incoming))
				new Thread(() -> e.accept(incoming, reply), "Communique Distribution Handoff").start();
		});
		return this;
	}

	public void listen(Filter filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this._listen(filter, handler);
	}

	public <T extends Predicate<Communique>> void listen(T filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this._listen(filter, handler);
	}

}
