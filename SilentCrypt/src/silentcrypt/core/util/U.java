package silentcrypt.core.util;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.BinaryOperator;
import java.util.function.Supplier;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class U
{
	private static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("LLL/dd/yyyy hh:mm:ss.SSS a").withZone(ZoneId.systemDefault()).withLocale(Locale.getDefault());

	public static boolean anyMatch(String first, String... matches)
	{
		for (String s : matches)
			if (s.equalsIgnoreCase(first))
				return true;
		return false;
	}

	private static void appendStackTrace(StringBuilder msg, Throwable err)
	{
		while (err != null)
		{
			msg.append("\n" + err.getClass().getSimpleName() + ": " + err.getMessage());
			msg.append(Arrays.stream(err.getStackTrace()).map(StackTraceElement::toString).reduce("     ", (a, b) -> a + "\n     " + b));
			err = err.getCause();
			if (err != null)
				msg.append("\nCaused By:");
		}
	}

	public static InputStream download(String url)
	{
		InputStream stream = null;
		try
		{
			HttpURLConnection.setFollowRedirects(true);
			HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();

			conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
			String encoding = conn.getContentEncoding();
			if (encoding != null && encoding.equalsIgnoreCase("gzip"))
				stream = new GZIPInputStream(conn.getInputStream());
			else if (encoding != null && encoding.equalsIgnoreCase("deflate"))
				stream = new InflaterInputStream(conn.getInputStream(), new Inflater(true));
			else
				stream = conn.getInputStream();
		} catch (IOException e)
		{
			e.printStackTrace();
		}
		return stream;
	}

	public static void e(String string)
	{
		U.e(string, null);
	}

	public static void e(String string, Throwable err)
	{
		StringBuilder msg = new StringBuilder(string);
		U.appendStackTrace(msg, err);
		U.printWithTag("ERROR", msg.toString());
	}

	public static boolean endsWith(String name, String... endings)
	{
		for (String s : endings)
			if (name.toLowerCase().endsWith(s.toLowerCase()))
				return true;
		return false;
	}

	private static String expandIfArray(Object in)
	{
		if (in == null)
			return "null";
		if (in instanceof int[])
			return Arrays.toString((int[]) in);
		if (in instanceof short[])
			return Arrays.toString((short[]) in);
		if (in instanceof byte[])
			return Arrays.toString((byte[]) in);
		if (in instanceof double[])
			return Arrays.toString((double[]) in);
		if (in instanceof float[])
			return Arrays.toString((float[]) in);
		if (in instanceof long[])
			return Arrays.toString((long[]) in);
		if (in instanceof char[])
			return Arrays.toString((char[]) in);
		if (in instanceof boolean[])
			return Arrays.toString((boolean[]) in);
		if (in instanceof Object[])
			return Arrays.toString((Object[]) in);
		return in.toString();
	}

	public static String toBase64(byte[] input)
	{
		return new String(Base64.getEncoder().encode(input));
	}

	public static byte[] fromBase64(String input)
	{
		return Base64.getDecoder().decode(input);
	}

	public static byte[] toBytes(String input)
	{
		try
		{
			return input.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e)
		{
			// We have big problems if we get here...
			throw new UnsupportedOperationException(e);
		}
	}

	@SafeVarargs
	public static <K, V> V getOrNew(K key, Supplier<V> srcOfNew, Map<K, V>... maps)
	{
		Map<K, V> dst = null;
		for (Map<K, V> cur : maps)
		{
			V res = cur.get(key);
			if (res != null)
				return res;
			dst = cur;
		}
		V res = srcOfNew.get();
		if (dst != null)
			dst.put(key, res);
		return res;
	}

	public static MappedByteBuffer map(Path p) throws IOException
	{
		FileChannel chan = FileChannel.open(p, StandardOpenOption.READ);
		return chan.map(MapMode.READ_ONLY, 0, chan.size());
	}

	public static void p(Object in)
	{
		U.p(U.expandIfArray(in));
	}

	public static void p(String in)
	{
		U.printWithTag("OUTPUT", in);
	}

	public static void printWithTag(String tag, Object in)
	{
		U.printWithTag(tag, U.expandIfArray(in));
	}

	public static void printWithTag(String tag, String message)
	{
		StringBuilder sb = new StringBuilder();
		sb.append('[').append(U.formatter.format(Instant.now())).append(']');
		sb.append('[').append(tag).append(']');
		sb.append(message);
		System.out.println(sb.toString());
	}

	public static byte[] readFully(InputStream is) throws IOException
	{
		return U.readFully(is, -1, true);
	}

	public static byte[] readFully(InputStream is, int length, boolean readAll) throws IOException
	{
		byte[] output =
		{};
		if (length == -1)
			length = Integer.MAX_VALUE;
		int pos = 0;
		while (pos < length)
		{
			int bytesToRead;
			if (pos >= output.length)
			{ // Only expand when there's no room
				bytesToRead = Math.min(length - pos, output.length + 1024);
				if (output.length < pos + bytesToRead)
					output = Arrays.copyOf(output, pos + bytesToRead);
			} else
				bytesToRead = output.length - pos;
			int cc = is.read(output, pos, bytesToRead);
			if (cc < 0)
				if (readAll && length != Integer.MAX_VALUE)
					throw new EOFException("Detect premature EOF");
				else
				{
					if (output.length != pos)
						output = Arrays.copyOf(output, pos);
					break;
				}
			pos += cc;
		}
		return output;
	}

	public static ByteBuffer readToBuffer(InputStream is, ByteBuffer dst) throws IOException
	{
		byte[] buff = new byte[1024];
		while (is.available() != 0)
		{
			int read = is.read(buff);
			dst.put(buff, 0, read);
		}
		dst.position(0);
		return dst;
	}

	public static void sleep(int millis)
	{
		U.sleep(millis, 0);
	}

	public static void sleep(long millis, int nanos)
	{
		try
		{
			Thread.sleep(millis, nanos);
		} catch (InterruptedException e)
		{
			U.e("Error sleeping... ", e);
		}
	}

	public static <T> Stream<T> streamFrom(Supplier<T> src)
	{
		return U.streamFrom(src, 0);
	}

	public static <T> Stream<T> streamFrom(Supplier<T> src, int characteristics)
	{
		return StreamSupport.stream(Spliterators.spliteratorUnknownSize(new Iterator<T>()
		{
			private T next = src.get();

			@Override
			public boolean hasNext()
			{
				return this.next != null;
			}

			@Override
			public T next()
			{
				T res = this.next;
				this.next = src.get();
				return res;
			}
		}, characteristics | Spliterator.NONNULL), false);
	}

	public static final <T> BinaryOperator<T> throwingMerger()
	{
		return (u, v) -> {
			throw new IllegalStateException(String.format("Duplicate key %s", u));
		};
	}

	public static void w(String msg)
	{
		U.printWithTag("WARN", msg);
	}

	public static void w(String string, IOException e)
	{
		StringBuilder res = new StringBuilder(string);
		U.appendStackTrace(res, e);
		U.w(res.toString());
	}

	@SafeVarargs
	public static <T> Stream<T> concat(Stream<? extends T>... streams)
	{
		Stream<T> res = Stream.empty();
		for (Stream<? extends T> s : streams)
			res = Stream.concat(res, s);
		return res;
	}

	public static <T> Stream<T> concat(Stream<Stream<? extends T>> streams)
	{
		Stream<T> res = Stream.empty();
		for (Stream<? extends T> s : (Iterable<Stream<? extends T>>) streams::iterator)
			res = Stream.concat(res, s);
		return res;
	}

	@SuppressWarnings("unchecked")
	public static <T> T quietCast(Object o)
	{
		return (T) o;
	}

	public static ByteBuffer toBuff(String string)
	{
		byte[] data = string.getBytes();
		ByteBuffer res = ByteBuffer.allocateDirect(data.length);
		res.put(data);
		res.rewind();
		return res;
	}
}
