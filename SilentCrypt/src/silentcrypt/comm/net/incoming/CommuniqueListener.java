package silentcrypt.comm.net.incoming;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;

import silentcrypt.comm.net.communique.Communique;

public class CommuniqueListener implements BiConsumer<Communique, Consumer<Communique>>, Predicate<Communique>
{
	private Predicate<Communique>							filter;
	private BiConsumer<Communique, Consumer<Communique>>	handler;

	public CommuniqueListener(Predicate<Communique> filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		this.filter = filter;
		this.handler = handler;
	}

	@Override
	public void accept(Communique c, Consumer<Communique> reply)
	{
		this.handler.accept(c, reply);
	}

	@Override
	public boolean test(Communique c)
	{
		return this.filter.test(c);
	}
}