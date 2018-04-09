package silentcrypt.comm.exception;

import java.io.IOException;

/**
 * Thrown when a message was expecting a response, and instead was rejected.
 *
 * @author Michael Wells
 */
public class MessageRejectedException extends IOException
{
	private static final long serialVersionUID = 841992865030814840L;

	public MessageRejectedException()
	{
		super();
	}

	public MessageRejectedException(String message)
	{
		super(message);
	}

	public MessageRejectedException(Throwable cause)
	{
		super(cause);
	}

	public MessageRejectedException(String message, Throwable cause)
	{
		super(message, cause);
	}
}
