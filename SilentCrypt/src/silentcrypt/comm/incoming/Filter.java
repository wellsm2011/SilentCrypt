package silentcrypt.comm.incoming;

import java.util.function.Predicate;

import silentcrypt.comm.communique.Communique;

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
