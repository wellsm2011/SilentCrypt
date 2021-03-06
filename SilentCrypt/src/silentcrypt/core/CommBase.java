package silentcrypt.core;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.bouncycastle.crypto.params.RSAKeyParameters;

import silentcrypt.comm.MessageType;
import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.MetaSpace;
import silentcrypt.comm.exception.MessageRejectedException;
import silentcrypt.core.CertAuthComm.CertAuthClient;
import silentcrypt.util.RsaKeyPair;

public abstract class CommBase
{
	public class Channel
	{
		private String						name;
		protected HashMap<String, UserData>	users	= new HashMap<>();
		private byte[]						key		= null;

		public Channel(String name)
		{
			this.name = name;
		}

		public void setKey(byte[] key)
		{
			this.key = key;
		}

		public byte[] getKey()
		{
			return this.key;
		}

		public Collection<UserData> getUsers()
		{
			return Collections.unmodifiableCollection(this.users.values());
		}

		protected void clearUsers()
		{
			this.users.clear();
		}

		protected void ensureContains(UserData data)
		{
			if (!this.users.containsValue(data))
				this.users.put(data.getUsername(), data);
		}

		public String getName()
		{
			return this.name;
		}

		public boolean join(long timeout)
		{
			if (CommBase.this instanceof CommClient)
			{
				Communique c = MessageType.CHANNEL_JOIN_REQUEST.create(CommBase.this.me.getUsername());
				return this.key != null;
			}
			throw new IllegalArgumentException("Method must be called from client.");
		}
	}

	public static final int	DEFAULT_PORT		= 7779;
	public static final int	TIMEOUT_MILLIS		= 11 * 1000;
	public static final int	HEARTBEAT_MILLIS	= 5 * 1000;

	protected HashMap<String, Channel>													activeChannels	= new HashMap<>();
	protected HashMap<String, UserData>													connectedUsers	= new HashMap<>();
	protected HashMap<MessageType, List<BiConsumer<Communique, Consumer<Communique>>>>	listeners		= new HashMap<>();
	protected UserData																	me;
	protected RsaKeyPair																myKey;
	protected RSAKeyParameters															caPublic		= null;

	public CommBase(String username, RsaKeyPair myKey)
	{
		this.me = new UserData(username, myKey.getPublicRsa(), Instant.now(), -1, null);
		this.myKey = myKey;

		for (MessageType t : MessageType.values())
			this.listeners.put(t, new ArrayList<>());
	}

	public void registerWithCa(InetSocketAddress caAddr) throws TimeoutException, MessageRejectedException, IllegalArgumentException
	{
		CertAuthClient c = CertAuthComm.client(caAddr);
		if (this.caPublic == null)
			this.caPublic = c.query();
		if (!this.me.hasCert())
			this.me.setCert(c.certify(this.myKey.getPublicRsa()), this.caPublic);
	}

	protected void processMsg(Communique msg, Consumer<Communique> reply)
	{
		MessageType mt = validate(msg, reply);
		if (mt != null)
		{
			List<BiConsumer<Communique, Consumer<Communique>>> listeners = this.listeners.get(mt);
			if (listeners.isEmpty())
				generateRejectMessage(msg, "Message ignored.");
			else
				for (BiConsumer<Communique, Consumer<Communique>> listener : listeners)
					listener.accept(msg, reply);
		}
	}

	public void listen(Consumer<Communique> listener, MessageType... types)
	{
		for (MessageType t : types)
			this.listeners.get(t).add((c, r) -> listener.accept(c));
	}

	protected void listen(BiConsumer<Communique, Consumer<Communique>> listener, MessageType... types)
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
			if (type.equals(MessageType.SERVER_JOIN_ANNOUNCEMENT) || type.equals(MessageType.AUTHENTICATION_RESPONSE))
			{
				RSAKeyParameters publicRsaKey = message.getField(2).data(RSAKeyParameters.class);
				byte[] cert = message.getField(3).data(byte[].class);
				UserData ud = new UserData(username, publicRsaKey, message.getTimestamp(), message.getConnectionId(), reply);
				try
				{
					ud.setCert(cert, this.caPublic);
				} catch (IllegalArgumentException ex)
				{
					reply.accept(generateRejectMessage(message, "Invalid certification supplied."));
					return null;
				}
				this.connectedUsers.put(username, ud);
			} else
			{
				reply.accept(generateRejectMessage(message, "User not authenticated."));
				return null;
			}
		}

		if (!message.validate(user.getPublicKey()))
		{
			reply.accept(generateRejectMessage(message, "Signature validation failed."));
			return null;
		}

		if (!user.updateLastMessage(message.getTimestamp()))
		{
			reply.accept(generateRejectMessage(message, "Invalid timestamp."));
			return null;
		}

		return type;
	}

	protected Communique generateRejectMessage(Communique message, String reason)
	{
		Communique reply = MessageType.MESSAGE_REJECT.create(this.me.getUsername());
		reply.add(this.me.getUsername()).add(reason).add(message.getTimestamp()).add(message.getField(0));
		MetaSpace ms = reply.getMetaSpace();
		ms.set(MetaSpace.RSA_SELF, this.myKey);
		reply.sign();

		return reply;
	}

	public Collection<Channel> myChannels()
	{
		return this.activeChannels.values().stream().filter(c -> Objects.nonNull(c.key)).collect(Collectors.toList());
	}

	public Collection<Channel> getChannels()
	{
		return Collections.unmodifiableCollection(this.activeChannels.values());
	}
}
