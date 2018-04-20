package silentcrypt.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.incoming.CommuniqueListener;

public abstract class CommBase
{
	public static final int	DEFAULT_PORT		= 7779;
	public static final int	TIMEOUT_MILLIS		= 11 * 1000;
	public static final int	HEARTBEAT_MILLIS	= 5 * 1000;

	private int port = DEFAULT_PORT;

	protected ConcurrentHashMap<String, UserData>					connectedUsers	= new ConcurrentHashMap<>();
	protected HashMap<MessageType, ArrayList<Consumer<Communique>>>	listeners		= new HashMap<>();
	protected UserData												me;

	public CommBase(UserData me)
	{
		this.me = me;

		for (MessageType t : MessageType.values())
			this.listeners.put(t, new ArrayList<>());
	}

	public CommuniqueListener getListener()
	{
		return new CommuniqueListener(c -> true, (c, reply) -> {

		});
	}

	protected MessageType validate(Communique message, Consumer<Communique> reply)
	{
		if (!message.isSigned())
			return null;

		MessageType type = MessageType.get(message);
		if (type == null || type == MessageType.AUTHENTICATION_REQUEST)
			return type;

		String username = message.getField(1).dataString();
		UserData user = this.connectedUsers.get(username);

		if (user == null)
		{
			reply.accept(rejectMessage(message, "User not authenticated."));
			return null;
		}

		if (!message.validate(user.getPublicKey()))
		{
			reply.accept(rejectMessage(message, "Signature validation failed."));
			return null;
		}

		return type;
	}

	protected Communique rejectMessage(Communique message, String reason)
	{
		Communique reply = MessageType.MESSAGE_REJECT.create(this.me.getUsername());
		reply.add(reason);
		reply.add(message.getTimestamp());
		reply.add(message.getField(0));

		return reply;
	}
}
