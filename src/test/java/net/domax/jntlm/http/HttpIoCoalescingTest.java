/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import lombok.val;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

/** Coalesced header/body writes (design D5 of optimize-pool-and-tunnel). */
class HttpIoCoalescingTest {

  private static final HttpMessage GET = request("GET http://example.com/ HTTP/1.1\r\n");

  /** Records each write and flush reaching the "socket". */
  private static final class CountingStream extends OutputStream {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    final List<Integer> writes = new ArrayList<>();
    int flushes;

    @Override
    public void write(int b) {
      bytes.write(b);
      writes.add(1);
    }

    @Override
    public void write(byte @NonNull [] b, int off, int len) {
      bytes.write(b, off, len);
      writes.add(len);
    }

    @Override
    public void flush() {
      flushes++;
    }
  }

  private static HttpMessage request(String startLine) {
    try {
      return HttpIo.recvHeaders(
          new ByteArrayInputStream((startLine + "Host: example.com\r\n\r\n").getBytes(ISO_8859_1)));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Relays one response the way {@code RequestForwarder} loop 1 does. */
  private static CountingStream relay(String raw) throws IOException {
    val in = new HttpInputStream(new ByteArrayInputStream(raw.getBytes(ISO_8859_1)));
    val response = HttpIo.recvHeaders(in);
    val socket = new CountingStream();
    val out = new BufferedOutputStream(socket, HttpIo.OUTPUT_BUFFER_SIZE);
    HttpIo.sendHeaders(out, response, !HttpIo.hasSmallFixedBody(GET, response));
    HttpIo.sendBody(out, in, GET, response);
    return socket;
  }

  @Test
  void smallFixedLengthResponseIsFlushedOnceInOneWrite() throws IOException {
    val raw = "HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n" + "b".repeat(512);
    try (val socket = relay(raw)) {
      assertEquals(raw, socket.bytes.toString(ISO_8859_1));
      assertEquals(1, socket.flushes);
      assertEquals(1, socket.writes.size());
    }
  }

  @Test
  void largeResponseFlushesHeadersBeforeTheBody() throws IOException {
    val head = "HTTP/1.1 200 OK\r\nContent-Length: 10485760\r\n\r\n";
    val raw = head + "c".repeat(10 * 1024 * 1024);
    try (val socket = relay(raw)) {
      assertEquals(raw.length(), socket.bytes.size());
      assertEquals(head.length(), socket.writes.getFirst(), "headers must leave on their own");
      assertTrue(socket.flushes >= 2);
    }
  }

  @Test
  void chunkedResponseIsUnchanged() throws IOException {
    val head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    val raw = head + "5\r\nhello\r\n0\r\n\r\n";
    try (val socket = relay(raw)) {
      assertArrayEquals(raw.getBytes(ISO_8859_1), socket.bytes.toByteArray());
      assertEquals(head.length(), socket.writes.getFirst(), "headers flushed before the body");
    }
  }

  @Test
  void smallBodyDecisionRules() {
    assertTrue(
        HttpIo.hasSmallFixedBody(GET, response("HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n")));
    assertFalse(
        HttpIo.hasSmallFixedBody(GET, response("HTTP/1.1 200 OK\r\nContent-Length: 8193\r\n")));
    assertFalse(
        HttpIo.hasSmallFixedBody(GET, response("HTTP/1.1 204 No Content\r\n")), "no body: flush");
    assertFalse(HttpIo.hasSmallFixedBody(GET, null), "body-less request: flush");

    val post = request("POST http://example.com/ HTTP/1.1\r\nContent-Length: 10\r\n");
    assertTrue(HttpIo.hasSmallFixedBody(post, null));
    val expect =
        request(
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 10\r\nExpect: 100-continue\r\n");
    assertFalse(HttpIo.hasSmallFixedBody(expect, null), "Expect waits for an interim response");
  }

  private static HttpMessage response(String head) {
    try {
      InputStream in = new ByteArrayInputStream((head + "\r\n").getBytes(ISO_8859_1));
      return HttpIo.recvHeaders(in);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
