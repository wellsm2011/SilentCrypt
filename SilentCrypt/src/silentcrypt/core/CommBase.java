package silentcrypt.core;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.core.CertAuthComm.CertAuthClient;
import silentcrypt.util.RsaKeyPair;

public abstract class CommBase
{
	public static final int	DEFAULT_PORT		= 7779;
	public static final int	TIMEOUT_MILLIS		= 11 * 1000;
	public static final int	HEARTBEAT_MILLIS	= 5 * 1000;

	protected ConcurrentHashMap<String, UserData>					connectedUsers	= new ConcurrentHashMap<>();
	protected HashMap<MessageType, ArrayList<Consumer<Communique>>>	listeners		= new HashMap<>();
	protected UserData												me;
	protected RsaKeyPair											myKey;
	protected RSAKeyParameters										caPublic;

	public CommBase(String username, RsaKeyPair myKey, InetSocketAddress caAddr) throws TimeoutException, MessageRejectedException
	{
		this.me = new UserData(username, myKey.getPublicRsa(), Instant.now(), -1, null);
		this.myKey = myKey;

		CertAuthClient c = CertAuthComm.client(caAddr);
		this.caPublic = c.query();
		this.me.setCert(c.certify(myKey.getPublicRsa()), this.caPublic);

		for (MessageType t : MessageType.values())
			this.listeners.put(t, new ArrayList<>());
	}

	protected void listen(Consumer<Communique> listener, MessageType... types)
	{
		for (MessageType t : types)
			this.listeners.get(t).add(listener);
	}

	protected MessageType validate(Communique message, Consumer<Communique> reply)
	{
		if (!message.isSigned())
			return null;

		MessageType type = MessageType.get(message);
		if (type == null || type == MessageType.AUTHENTICATION_REQUEST)
			return type;

		String username = message.getField(1).data(String.class);
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
		reply.add(this.me.getUsername()).add(reason).add(message.getTimestamp()).add(message.getField(0));

		return reply;
	}
}
