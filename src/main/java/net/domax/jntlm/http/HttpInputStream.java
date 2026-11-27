/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import lombok.val;

/**
 * Unsynchronized buffered input stream with fast HTTP line scanning. Not in CNTLM: replaces the
 * per-byte reads of CNTLM's {@code so_recvln} (and {@link java.io.BufferedInputStream}'s per-call
 * locking) with a scan of the buffer for {@code LF}.
 *
 * <p>Not thread-safe by contract: each connection's input is read by one thread at a time.
 */
public final class HttpInputStream extends InputStream {

  /** Size of the read buffer. */
  public static final int BUFFER_SIZE = 16 * 1024;

  private final InputStream in;
  private final byte[] buf = new byte[BUFFER_SIZE];
  private int pos;
  private int limit;
  private byte[] lineBuf = new byte[256];

  public HttpInputStream(InputStream in) {
    this.in = Objects.requireNonNull(in);
  }

  /** Refills the (empty) buffer; returns the number of bytes read or {@code -1} on EOF. */
  private int fill() throws IOException {
    pos = 0;
    limit = 0;
    int n;
    do n = in.read(buf, 0, buf.length);
    while (n == 0);
    if (n > 0) limit = n;
    return n;
  }

  @Override
  public int read() throws IOException {
    if (pos >= limit && fill() < 0) return -1;
    return buf[pos++] & 0xff;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    Objects.checkFromIndexSize(off, len, b.length);
    if (len == 0) return 0;
    if (pos >= limit) {
      // Large read with nothing buffered: skip the intermediate copy.
      if (len >= buf.length) return in.read(b, off, len);
      if (fill() < 0) return -1;
    }
    val n = Math.min(len, limit - pos);
    System.arraycopy(buf, pos, b, off, n);
    pos += n;
    return n;
  }

  @Override
  public int available() throws IOException {
    return (limit - pos) + in.available();
  }

  @Override
  public void close() throws IOException {
    in.close();
  }

  /**
   * Reads a single line terminated by LF, keeping the terminator. Returns {@code null} on EOF
   * before any byte; raises {@link EOFException} on EOF mid-line, an {@link HttpProtocolException}
   * with {@code overLimit} when longer than {@code max} bytes, and with {@code malformed} on a CR
   * not immediately followed by LF.
   */
  @SuppressWarnings("java:S3776")
  public String readLine(int max, int overLimit, int malformed) throws IOException {
    var count = 0;
    while (true) {
      if (pos >= limit && fill() < 0) {
        if (count == 0) return null;
        throw new EOFException("EOF inside line");
      }
      val allowed = max - count;
      val scanEnd = pos + Math.clamp(allowed, 0, limit - pos);
      var lf = pos;
      while (lf < scanEnd && buf[lf] != '\n') lf++;
      if (lf < scanEnd) {
        val segment = lf - pos + 1;
        final String line;
        if (count == 0) {
          checkCr(buf, pos, segment, malformed);
          line = new String(buf, pos, segment, StandardCharsets.ISO_8859_1);
        } else {
          append(count, segment);
          count += segment;
          checkCr(lineBuf, 0, count, malformed);
          line = new String(lineBuf, 0, count, StandardCharsets.ISO_8859_1);
        }
        pos += segment;
        return line;
      }
      if (scanEnd < limit) throw new HttpProtocolException(overLimit, "line too long");
      val segment = limit - pos;
      append(count, segment);
      count += segment;
      pos = limit;
    }
  }

  private void append(int count, int segment) {
    if (count + segment > lineBuf.length)
      lineBuf = Arrays.copyOf(lineBuf, Math.max(lineBuf.length * 2, count + segment));
    System.arraycopy(buf, pos, lineBuf, count, segment);
  }

  private static void checkCr(byte[] b, int off, int len, int malformed)
      throws HttpProtocolException {
    val crAllowedAt = len >= 2 && b[off + len - 2] == '\r' ? off + len - 2 : -1;
    for (var i = off; i < off + len - 1; i++)
      if (b[i] == '\r' && i != crAllowedAt) throw new HttpProtocolException(malformed, "bare CR");
  }

  /** Writes any buffered, unread bytes to {@code out} (without flushing); returns their count. */
  public int drainBuffered(OutputStream out) throws IOException {
    val n = limit - pos;
    if (n > 0) out.write(buf, pos, n);
    pos = limit;
    return n;
  }

  /**
   * Returns true if the peer has closed the connection. With buffered data the peer is considered
   * open; otherwise one buffer fill is attempted under a 1&nbsp;ms read timeout: EOF means closed,
   * data means open (and is kept buffered), a timeout means open with no pending data.
   */
  public boolean peekClosed(Socket socket) {
    if (pos < limit) return false;
    if (socket.isClosed() || !socket.isConnected()) return true;
    int oldTimeout;
    try {
      oldTimeout = socket.getSoTimeout();
    } catch (IOException e) {
      return true;
    }
    try {
      socket.setSoTimeout(1);
      return fill() < 0;
    } catch (SocketTimeoutException e) {
      return false;
    } catch (IOException e) {
      return true;
    } finally {
      try {
        socket.setSoTimeout(oldTimeout);
      } catch (IOException ignored) {
        // ignore
      }
    }
  }
}
