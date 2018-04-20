package silentcrypt.comm;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import silentcrypt.comm.communique.Communique;
import silentcrypt.comm.communique.Encryption;

public enum MessageType
{
	/**
	 * Merely a keep-alive message.
	 */
	HEARTBEAT(-1, 0),
	/**
	 * Extra fields: Reason, Original Message Timestamp, Original Message Type
	 */
	MESSAGE_REJECT(0, 5),
	/**
	 * Extra fields: public RSA key, certification
	 */
	AUTHENTICATION_REQUEST(1, 4),
	/**
	 * Extra fields: public RSA key, certification (echo's request)
	 */
	AUTHENTICATION_RESPONSE(2, 4),
	/**
	 * Extra fields: channel name (optional)
	 */
	INFORMATION_REQUEST(3, 2),
	/**
	 * Extra fields: channel name (blank if listing channels), list of items (if listing clients, fields alternate
	 * between usernames and public RSA keys)
	 */
	INFORMATION_RESPONSE(4, 3),
	/**
	 * Extra fields: channel name
	 */
	CHANNEL_JOIN_REQUEST(5, 3),
	/**
	 * Extra fields: channel name
	 */
	CHANNEL_CREATE_REQUEST(6, 3),
	/**
	 * Extra fields: channel name, joining client's public RSA key
	 */
	CHANNEL_JOIN_AUTHENTICATION(7, 4),
	/**
	 * Extra fields: channel name, client's username, AES session key (encrypted with client's public key)<br>
	 * Note: uses original client's username instead of server's
	 */
	CHANNEL_JOIN_ACCEPT(8, 5),
	/**
	 * Extra fields: channel name, client's username
	 */
	CHANNEL_JOIN_REJECT(9, 4),
	/**
	 * Extra fields: channel name
	 */
	CHANNEL_LEAVE_NOTICE(10, 3),
	/**
	 * Extra fields: channel name, creator's username
	 */
	CHANNEL_CREATION_ANNOUNCEMENT(11, 4),
	/**
	 * Extra fields: channel name<br>
	 * Note: uses original client's username instead of server's
	 */
	CHANNEL_JOIN_ANNOUNCEMENT(12, 3),
	/**
	 * Extra fields: channel name<br>
	 * Note: uses original client's username instead of server's
	 */
	CHANNEL_LEAVE_ANNOUNCEMENT(13, 3),
	/**
	 * Extra fields: Client's public RSA key, Client's Certification<br>
	 * Note: uses original client's username instead of server's
	 */
	SERVER_JOIN_ANNOUNCEMENT(14, 4),
	/**
	 * Extra fields: Client's public RSA key, Client's Certification<br>
	 * Note: uses original client's username instead of server's
	 */
	SERVER_LEAVE_ANNOUNCEMENT(15, 4),
	/**
	 * Extra fields: Channel name, data (may be multiple fields)
	 */
	CHANNEL_MESSAGE(16, 4),
	/**
	 * Extra fields: username, data (may be multiple fields)
	 */
	CLIENT_MESSAGE(17, 4);

	private static final Map<Short, MessageType> reverse;

	static
	{
		reverse = Collections.unmodifiableMap(Arrays.stream(MessageType.values()).collect(Collectors.toMap(d -> d.id, d -> d)));
	}

	/**
	 * Returns the message type for a given ID.
	 *
	 * @param id
	 * @return
	 */
	public static MessageType get(int id)
	{
		return MessageType.reverse.get(id);
	}

	/**
	 * @param id
	 * @return true iff {@link #get(int)} would return a non-null value.
	 */
	public static boolean isKnown(short id)
	{
		return MessageType.reverse.containsKey(id);
	}

	/**
	 * Returns the message type of a given Communique, validating that the basic structure of fields matches the
	 * message. If this method returns non-null, the Communique is guaranteed to have at least the minimum number of
	 * fields, and the first two fields are guaranteed to be unencrypted, and the first field describes a valid message
	 * type.
	 *
	 * @param c
	 * @return
	 */
	public static MessageType get(Communique c)
	{
		if (c.fieldCount() < 2)
			return null;

		if (c.getField(0).getEncryption() != Encryption.Unencrypted || c.getField(0).getEncryption() != Encryption.Unencrypted)
			return null;

		MessageType type = get(c.getField(0).encodedData().getShort());
		if (type == null || c.fieldCount() < type.minimumFields)
			return null;

		return type;
	}

	private short	id;
	private int		minimumFields;

	private MessageType(int id, int minimumFields)
	{
		this.id = (short) id;
		this.minimumFields = minimumFields;
	}

	public int getId()
	{
		return this.id;
	}

	public int getMinimumFieldCount()
	{
		return this.minimumFields;
	}

	public Communique create(String username)
	{
		return new Communique().add(ByteBuffer.allocate(Short.BYTES).putShort(this.id).array()).add(username);
	}
}
