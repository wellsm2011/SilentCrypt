package silentcrypt.comm.incoming;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;

import silentcrypt.comm.communique.Communique;

/**
 * Represents the pairing of a Filter which tests Communiques to decide whether to receive them and a BiConsumer which
 * processes accepted Communiques.
 *
 * @author Michael Wells
 * @author Andrew Binns
 */
public class CommuniqueListener implements Filter, BiConsumer<Communique, Consumer<Communique>>
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