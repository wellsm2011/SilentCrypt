package silentcrypt.comm.exception;

/**
 * @author Michael Wells
 * @author Andrew Binns
 */
public class DecodingException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	public DecodingException(String string)
	{
		super(string);
	}

	public DecodingException(String string, Throwable cause)
	{
		super(string, cause);
	}
}
