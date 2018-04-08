package silentcrypt.comm.net.exception;

import java.io.IOException;

/**
 * @author Michael
 * @author Andrew
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
