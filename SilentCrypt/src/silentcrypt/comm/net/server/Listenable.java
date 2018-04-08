package silentcrypt.comm.net.server;

import java.util.function.BiConsumer;
import java.util.function.Consumer;

import silentcrypt.comm.net.communique.Communique;
import silentcrypt.comm.net.incoming.CommuniqueListener;
import silentcrypt.comm.net.incoming.Filter;

/**
 * @author Michael Wells
 * @param <T>
 *            the class of the parent object which is implementing Listenable.
 */
@FunctionalInterface
public interface Listenable<T>
{
	/**
	 * Registers a new listener which receives Communiques.
	 *
	 * @param listener
	 * @return this object
	 */
	public T listen(CommuniqueListener listener);

	/**
	 * Registers a new listener which receives Communiques.
	 *
	 * @param filter
	 * @param handler
	 * @return this object.
	 */
	public default T listen(Filter filter, BiConsumer<Communique, Consumer<Communique>> handler)
	{
		return this.listen(new CommuniqueListener(filter, handler));
	}

	/**
	 * Registers a new listener which receives all Communiques.
	 *
	 * @param handler
	 * @return this object.
	 */
	public default T listen(BiConsumer<Communique, Consumer<Communique>> handler)
	{
		return this.listen(c -> true, handler);
	}
}
