package silentcrypt.comm.net.incoming;

import java.util.function.Predicate;

import silentcrypt.comm.net.communique.Communique;

/**
 * @author Andrew Binns
 */
public interface Filter extends Predicate<Communique>
{
	public static Filter all()
	{
		return c -> true;
	}

	public static Filter by(Predicate<Communique> pred)
	{
		return c -> pred.test(c);
	}
}
