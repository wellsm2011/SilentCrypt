package silentcrypt.comm.net.server;

/**
 * @author Andrew
 */
enum AerisStd
{
	SERVICE_REGISTRATION("AERIS-SERVICE-REGISTRATION"),
	KEEP_ALIVE("AERIS-SERVICE-KEEPALIVE");

	public static final int	PORT				= 4242;
	public static final int	HEARTBEAT_PERIOD	= 5000;
	public static final int	RETRY_PERIOD		= 3000;

	private final String id;

	AerisStd(String id)
	{
		this.id = id;
	}

	public String getId()
	{
		return this.id;
	}
}
