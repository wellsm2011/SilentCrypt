package silentcrypt.comm.exception;

/**
 * @author Andrew Binns
 */
public class EncodingException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	public EncodingException(String string)
	{
		super(string);
	}

	public EncodingException(String string, Throwable cause)
	{
		super(string, cause);
	}

}
