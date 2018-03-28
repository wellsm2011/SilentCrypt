package backend.stdcomm.incoming;

import java.util.function.Predicate;

import backend.stdcomm.communique.Communique;

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
