package silentcrypt.comm.exception;

import java.io.IOException;

/**
 * @author Michael Wells
 * @author Andrew Binns
 */
public class DecodingException extends IOException
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
