/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Random;
import lombok.val;
import org.junit.jupiter.api.Test;

class HttpInputStreamTest {

  private static final int MAX = 64 * 1024;

  /** Delivers at most one byte per {@code read(byte[],int,int)} call. */
  private static InputStream trickle(byte[] data) {
    return new ByteArrayInputStream(data) {
      @Override
      public synchronized int read(byte[] b, int off, int len) {
        return super.read(b, off, Math.min(len, 1));
      }
    };
  }

  private static HttpInputStream stream(String s) {
    return new HttpInputStream(new ByteArrayInputStream(s.getBytes(ISO_8859_1)));
  }

  private static String line(HttpInputStream in) throws IOException {
    return in.readLine(MAX, 431, 400);
  }

  @Test
  void readsLinesDeliveredOneByteAtATime() throws IOException {
    val in = new HttpInputStream(trickle("GET / HTTP/1.1\r\nHost: a\r\n\r\n".getBytes(ISO_8859_1)));
    assertEquals("GET / HTTP/1.1\r\n", line(in));
    assertEquals("Host: a\r\n", line(in));
    assertEquals("\r\n", line(in));
    assertNull(line(in));
  }

  @Test
  void readsLineSpanningBufferRefill() throws IOException {
    val prefix = "x".repeat(HttpInputStream.BUFFER_SIZE - 5);
    val in = stream(prefix + "\r\nabcdefghij-long-header-value\r\nnext\n");
    assertEquals(prefix + "\r\n", line(in));
    assertEquals("abcdefghij-long-header-value\r\n", line(in));
    assertEquals("next\n", line(in));
    assertNull(line(in));
  }

  @Test
  void readsVeryLongLineAcrossSeveralRefills() throws IOException {
    val longLine = "y".repeat(3 * HttpInputStream.BUFFER_SIZE + 7) + "\r\n";
    assertEquals(longLine, line(stream(longLine)));
  }

  @Test
  void eofMidLineRaisesEofExceptionAsBefore() throws IOException {
    val in = stream("complete\r\npartial");
    assertEquals("complete\r\n", line(in));
    assertThrows(EOFException.class, () -> line(in));
  }

  @SuppressWarnings("resource")
  @Test
  void lineLongerThanMaxIsRejected() throws IOException {
    val e =
        assertThrows(
            HttpProtocolException.class, () -> stream("abcdefgh\r\n").readLine(9, 431, 400));
    assertEquals(431, e.status());
    // Exactly max bytes including the terminator is accepted.
    assertEquals("abcdefgh\r\n", stream("abcdefgh\r\n").readLine(10, 431, 400));
    val across = "z".repeat(HttpInputStream.BUFFER_SIZE + 10) + "\n";
    assertEquals(
        431,
        assertThrows(
                HttpProtocolException.class,
                () -> stream(across).readLine(HttpInputStream.BUFFER_SIZE + 5, 431, 400))
            .status());
  }

  @Test
  void bareCrIsMalformed() {
    val e = assertThrows(HttpProtocolException.class, () -> line(stream("a\rb\r\n")));
    assertEquals(400, e.status());
    assertThrows(HttpProtocolException.class, () -> line(stream("a\r\r\n")));
  }

  @Test
  void bulkReadAfterLineReturnsBufferedBytesFirst() throws IOException {
    val in = stream("HTTP/1.1 200 OK\r\n0123456789");
    assertEquals("HTTP/1.1 200 OK\r\n", line(in));
    assertEquals(10, in.available());
    val buf = new byte[64 * 1024];
    val n = in.read(buf, 0, buf.length);
    assertEquals("0123456789", new String(buf, 0, n, ISO_8859_1));
    assertEquals(-1, in.read(buf, 0, buf.length));
    assertEquals(-1, in.read());
  }

  @Test
  void largeReadWithEmptyBufferBypassesBuffer() throws IOException {
    val data = new byte[100_000];
    new Random(1).nextBytes(data);
    val in = new HttpInputStream(new ByteArrayInputStream(data));
    val out = new ByteArrayOutputStream();
    val buf = new byte[HttpInputStream.BUFFER_SIZE];
    int n;
    while ((n = in.read(buf, 0, buf.length)) != -1) out.write(buf, 0, n);
    assertArrayEquals(data, out.toByteArray());
  }

  @Test
  void drainBufferedReturnsExactlyTheUnreadBytes() throws IOException {
    val in = stream("HTTP/1.1 200 Connection established\r\n\r\nTLS-bytes");
    assertEquals("HTTP/1.1 200 Connection established\r\n", line(in));
    assertEquals("\r\n", line(in));
    val out = new ByteArrayOutputStream();
    assertEquals(9, in.drainBuffered(out));
    assertEquals("TLS-bytes", out.toString(ISO_8859_1));
    assertEquals(0, in.drainBuffered(out));
  }

  @Test
  void matchesByteLoopOnRandomInput() throws IOException {
    val rnd = new Random(42);
    for (int round = 0; round < 200; round++) {
      val data = new byte[rnd.nextInt(40_000)];
      for (int i = 0; i < data.length; i++) data[i] = (byte) "ab\r\n:x \n".charAt(rnd.nextInt(8));
      val max = 1 + rnd.nextInt(40_000);
      val expected = referenceLines(new ByteArrayInputStream(data), max);
      val actual =
          referenceLinesOf(
              new HttpInputStream(
                  rnd.nextBoolean() ? new ByteArrayInputStream(data) : trickle(data)),
              max);
      assertEquals(expected, actual, "round " + round);
    }
  }

  private static String referenceLines(InputStream in, int max) {
    val sb = new StringBuilder();
    try {
      String l;
      while ((l = referenceReadLine(in, max)) != null) sb.append('[').append(l).append(']');
    } catch (IOException e) {
      sb.append(e.getClass().getSimpleName());
      if (e instanceof HttpProtocolException p) sb.append(p.status());
    }
    return sb.toString();
  }

  private static String referenceLinesOf(HttpInputStream in, int max) {
    val sb = new StringBuilder();
    try {
      String l;
      while ((l = in.readLine(max, 431, 400)) != null) sb.append('[').append(l).append(']');
    } catch (IOException e) {
      sb.append(e.getClass().getSimpleName());
      if (e instanceof HttpProtocolException p) sb.append(p.status());
    }
    return sb.toString();
  }

  /** The pre-existing byte-by-byte implementation from {@code HttpIo.readLine}. */
  private static String referenceReadLine(InputStream in, int max) throws IOException {
    val baos = new ByteArrayOutputStream(128);
    int c;
    while ((c = in.read()) != -1) {
      if (baos.size() >= max) throw new HttpProtocolException(431, "line too long");
      baos.write(c);
      if (c == '\n') break;
    }
    if (baos.size() == 0) return null;
    if (c != '\n') throw new EOFException("EOF inside line");
    val bytes = baos.toByteArray();
    val crAllowedAt = bytes.length >= 2 && bytes[bytes.length - 2] == '\r' ? bytes.length - 2 : -1;
    for (var i = 0; i < bytes.length - 1; i++)
      if (bytes[i] == '\r' && i != crAllowedAt) throw new HttpProtocolException(400, "bare CR");
    return new String(bytes, ISO_8859_1);
  }

  @Test
  void peekClosedDetectsEofAndKeepsPendingData() throws IOException {
    try (val server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        val client = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
        val accepted = server.accept()) {
      val in = new HttpInputStream(accepted.getInputStream());
      assertFalse(in.peekClosed(accepted), "idle open peer");
      client.getOutputStream().write("hi\n".getBytes(ISO_8859_1));
      client.getOutputStream().flush();
      var deadline = System.currentTimeMillis() + 2000;
      while (in.available() == 0 && System.currentTimeMillis() < deadline) Thread.onSpinWait();
      assertFalse(in.peekClosed(accepted), "peer with pending data");
      assertEquals("hi\n", line(in), "peeked data must not be lost");
      client.close();
      deadline = System.currentTimeMillis() + 2000;
      var closed = false;
      while (!closed && System.currentTimeMillis() < deadline) closed = in.peekClosed(accepted);
      assertTrue(closed);
      assertEquals(0, accepted.getSoTimeout(), "timeout restored");
    }
  }

  @Test
  void singleByteReadsAfterRefill() throws IOException {
    val data = new byte[HttpInputStream.BUFFER_SIZE + 3];
    Arrays.fill(data, (byte) 7);
    val in = new HttpInputStream(new ByteArrayInputStream(data));
    for (int i = 0; i < data.length; i++) assertEquals(7, in.read());
    assertEquals(-1, in.read());
  }
}
