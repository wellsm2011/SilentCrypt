package silentcrypt.comm.net.exception;

import java.io.IOException;

/**
 * @author Andrew
 * @author Michael
 */
public class DecodingException extends IOException
{
	private static final long serialVersionUID = 1L;

	public DecodingException(String string)
	{
		super(string);
	}

}
