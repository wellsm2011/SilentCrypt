package silentcrypt.comm.net.exception;

import java.io.IOException;

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
