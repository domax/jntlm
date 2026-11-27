/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Parser-level tests for strict HTTP framing ({@code specs/http-message-framing}). */
class HttpIoFramingTest {

  private static final String REQ = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n";
  private static final String RESP = "HTTP/1.1 200 OK\r\n";

  private static InputStream in(String s) {
    return new ByteArrayInputStream(s.getBytes(StandardCharsets.ISO_8859_1));
  }

  private static int status(String raw) {
    return assertThrows(HttpProtocolException.class, () -> HttpIo.recvHeaders(in(raw))).status();
  }

  private static int status(String raw, HttpLimits limits) {
    return assertThrows(HttpProtocolException.class, () -> HttpIo.recvHeaders(in(raw), limits))
        .status();
  }

  // ------------------------------------------------------------ malformed requests

  @ParameterizedTest
  @ValueSource(
      strings = {
        REQ + "Content-Length : 5\r\n\r\n",
        REQ + "X-Broken\r\n\r\n",
        REQ + " folded\r\n\r\n",
        REQ + "\tfolded\r\n\r\n",
        REQ + "X-A: a\rb\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\r\nHost: x\r\n\r\n",
        "GARBAGE\r\n\r\n",
        "GET http://example.com/  HTTP/1.1\r\nHost: x\r\n\r\n",
        REQ + "X(bad): 1\r\n\r\n",
        REQ + ": empty\r\n\r\n",
        "GET / HTTP/1.1\r\n\r\n",
        "GET http://example.com:99999/ HTTP/1.1\r\n\r\n",
        "GET http://example.com:abc/ HTTP/1.1\r\n\r\n",
      })
  void malformedRequestIs400(String raw) {
    assertEquals(400, status(raw));
  }

  @Test
  void cleanEofBeforeFirstByteReturnsNull() throws IOException {
    assertNull(HttpIo.recvHeaders(in("")));
  }

  @Test
  void truncatedHeaderSectionThrowsEof() {
    assertThrows(EOFException.class, () -> HttpIo.recvHeaders(in(REQ)));
    assertThrows(EOFException.class, () -> HttpIo.recvHeaders(in("GET http://x/ HTT")));
  }

  @Test
  void leadingEmptyLinesAreIgnored() throws IOException {
    assertNotNull(HttpIo.recvHeaders(in("\r\n" + REQ + "\r\n")));
  }

  @Test
  void validRequestKeepsHeaderOrderAndValues() throws IOException {
    HttpMessage m = HttpIo.recvHeaders(in(REQ + "A: 1\r\nB:  2 \r\nA: 3\r\n\r\n"));
    assertNotNull(m);
    assertEquals(
        List.of(
            new HttpHeaders.Header("Host", "example.com"),
            new HttpHeaders.Header("A", "1"),
            new HttpHeaders.Header("B", "2"),
            new HttpHeaders.Header("A", "3")),
        m.getHeaders().all());
    assertEquals("example.com", m.getHost());
    assertEquals(80, m.getPort());
  }

  @Test
  void lfOnlyLineEndingsAreAccepted() throws IOException {
    assertNotNull(HttpIo.recvHeaders(in("GET http://x/ HTTP/1.1\nHost: x\n\n")));
  }

  // ------------------------------------------------------------ malformed responses

  @ParameterizedTest
  @ValueSource(
      strings = {
        RESP + "Transfer-Encoding : chunked\r\n\r\n",
        RESP + "Content-Length: 12x\r\n\r\n",
        RESP + "Content-Length: 1\r\nContent-Length: 2\r\n\r\n",
        RESP + "Broken\r\n\r\n",
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1\r\n\r\n",
      })
  void malformedResponseIs502(String raw) {
    assertEquals(502, status(raw));
  }

  // ------------------------------------------------------------ Content-Length

  @ParameterizedTest
  @ValueSource(strings = {"-5", "abc", "+5", "", "1234567890123456789", "5, 6"})
  void invalidRequestContentLengthIs400(String cl) {
    assertEquals(400, status(REQ + "Content-Length: " + cl + "\r\n\r\n"));
  }

  @Test
  void conflictingDuplicateContentLengthIs400() {
    assertEquals(400, status(REQ + "Content-Length: 5\r\nContent-Length: 6\r\n\r\n"));
  }

  @Test
  void identicalDuplicateContentLengthCollapses() throws IOException {
    HttpMessage m =
        HttpIo.recvHeaders(in(REQ + "Content-Length: 5\r\nX: y\r\nContent-Length: 5\r\n\r\n"));
    assertEquals(List.of("5"), m.getHeaders().getAll("Content-Length"));
    assertEquals(5, HttpIo.httpHasBody(m, null));

    HttpMessage list = HttpIo.recvHeaders(in(REQ + "Content-Length: 7, 7\r\n\r\n"));
    assertEquals(List.of("7"), list.getHeaders().getAll("Content-Length"));
  }

  // ------------------------------------------------------------ Transfer-Encoding

  @Test
  void requestWithTeAndClIs400() {
    assertEquals(400, status(REQ + "Transfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"xchunked", "chunked, gzip", "gzip"})
  void requestWithNonChunkedFinalCodingIs400(String te) {
    assertEquals(400, status(REQ + "Transfer-Encoding: " + te + "\r\n\r\n"));
  }

  @Test
  void requestWithChunkedFinalCodingIsChunked() throws IOException {
    HttpMessage m = HttpIo.recvHeaders(in(REQ + "Transfer-Encoding: gzip, chunked\r\n\r\n"));
    assertTrue(HttpIo.isChunked(m));
    assertEquals(HttpIo.CHUNKED, HttpIo.httpHasBody(m, null));

    HttpMessage split =
        HttpIo.recvHeaders(
            in(REQ + "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"));
    assertTrue(HttpIo.isChunked(split));
  }

  @Test
  void responseWithTeAndClDropsClAndIsNotReusable() throws IOException {
    HttpMessage m =
        HttpIo.recvHeaders(in(RESP + "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"));
    assertFalse(m.getHeaders().contains("Content-Length"));
    assertTrue(HttpIo.isChunked(m));
    assertFalse(m.isReusable());
    assertFalse(m.copy().isReusable());
  }

  @Test
  void responseWithNonChunkedTeIsReadUntilCloseAndNotReusable() throws IOException {
    HttpMessage m = HttpIo.recvHeaders(in(RESP + "Transfer-Encoding: gzip\r\n\r\n"));
    assertEquals(HttpIo.UNTIL_CLOSE, HttpIo.httpHasBody(null, m));
    assertFalse(m.isReusable());
    assertFalse(HttpIo.isCleanlyFramed(null, m));
  }

  // ------------------------------------------------------------ body detection

  @Test
  void getAndHeadRequestBodiesFollowContentLength() throws IOException {
    HttpMessage get = HttpIo.recvHeaders(in(REQ + "Content-Length: 4\r\n\r\n"));
    assertEquals(4, HttpIo.httpHasBody(get, null));

    HttpMessage head =
        HttpIo.recvHeaders(
            in("HEAD http://x/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"));
    assertEquals(HttpIo.CHUNKED, HttpIo.httpHasBody(head, null));
  }

  @Test
  void requestWithoutFramingHasNoBody() throws IOException {
    HttpMessage post =
        HttpIo.recvHeaders(
            in("POST http://x/ HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\n"));
    assertEquals(0, HttpIo.httpHasBody(post, null));
  }

  @Test
  void responseFramingClassification() throws IOException {
    HttpMessage unframed = HttpIo.recvHeaders(in(RESP + "Content-Type: text/plain\r\n\r\n"));
    assertEquals(HttpIo.UNTIL_CLOSE, HttpIo.httpHasBody(null, unframed));
    assertFalse(HttpIo.isCleanlyFramed(null, unframed));

    HttpMessage framed = HttpIo.recvHeaders(in(RESP + "Content-Length: 0\r\n\r\n"));
    assertTrue(HttpIo.isCleanlyFramed(null, framed));

    HttpMessage noContent = HttpIo.recvHeaders(in("HTTP/1.1 204 No Content\r\n\r\n"));
    assertEquals(0, HttpIo.httpHasBody(null, noContent));
    assertTrue(HttpIo.isCleanlyFramed(null, noContent));
  }

  // ------------------------------------------------------------ header limits

  @Test
  void tooManyHeaderLinesIs431ForRequestAnd502ForResponse() {
    StringBuilder headers = new StringBuilder();
    for (int i = 0; i < 257; i++) headers.append("X-").append(i).append(": v\r\n");
    assertEquals(431, status(REQ + headers + "\r\n"));
    assertEquals(502, status(RESP + headers + "\r\n"));
  }

  @Test
  void exactlyMaxHeaderLinesIsAccepted() throws IOException {
    StringBuilder headers = new StringBuilder();
    for (int i = 0; i < 255; i++) headers.append("X-").append(i).append(": v\r\n");
    assertNotNull(HttpIo.recvHeaders(in(REQ + headers + "\r\n")));
  }

  @Test
  void oversizedHeaderSectionIs431() {
    String big = REQ + "X-Big: " + "a".repeat(2000) + "\r\n\r\n";
    assertEquals(431, status(big, new HttpLimits(1024, 256)));
    assertEquals(
        431,
        status(
            "GET http://x/" + "a".repeat(2000) + " HTTP/1.1\r\n\r\n", new HttpLimits(1024, 256)));
    assertEquals(
        502, status(RESP + "X-Big: " + "a".repeat(2000) + "\r\n\r\n", new HttpLimits(1024, 256)));
  }

  // ------------------------------------------------------------ bodies

  private static byte[] send(String head, String body) throws IOException {
    HttpMessage resp = HttpIo.recvHeaders(in(head));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    HttpIo.sendBody(out, in(body), null, resp);
    return out.toByteArray();
  }

  @Test
  void validChunkedBodyIsRelayedVerbatim() throws IOException {
    String body = "4;ext=1\r\nWiki\r\n5 \r\npedia\r\n0\r\nX-Trailer: t\r\n\r\n";
    byte[] out = send(RESP + "Transfer-Encoding: chunked\r\n\r\n", body);
    assertArrayEquals(body.getBytes(StandardCharsets.ISO_8859_1), out);
  }

  @ParameterizedTest
  @ValueSource(strings = {"zz\r\n", "\r\n", "12345678901234567\r\n", "4 x\r\nWiki\r\n0\r\n\r\n"})
  void invalidChunkSizeIsRejected(String body) {
    assertThrows(
        HttpProtocolException.class, () -> send(RESP + "Transfer-Encoding: chunked\r\n\r\n", body));
  }

  @Test
  void chunkDataNotFollowedByCrlfIsRejected() {
    assertThrows(
        HttpProtocolException.class,
        () -> send(RESP + "Transfer-Encoding: chunked\r\n\r\n", "4\r\nWikiXX0\r\n\r\n"));
  }

  @Test
  void truncatedChunkedBodyThrowsEof() {
    assertThrows(
        EOFException.class, () -> send(RESP + "Transfer-Encoding: chunked\r\n\r\n", "4\r\nWi"));
    assertThrows(
        EOFException.class,
        () -> send(RESP + "Transfer-Encoding: chunked\r\n\r\n", "4\r\nWiki\r\n"));
  }

  @Test
  void tooManyTrailersAreRejected() {
    StringBuilder trailers = new StringBuilder();
    for (int i = 0; i < 257; i++) trailers.append("T-").append(i).append(": v\r\n");
    assertThrows(
        HttpProtocolException.class,
        () -> send(RESP + "Transfer-Encoding: chunked\r\n\r\n", "0\r\n" + trailers + "\r\n"));
  }

  @Test
  void truncatedFixedBodyRelaysReceivedBytesThenThrowsEof() throws IOException {
    HttpMessage resp = HttpIo.recvHeaders(in(RESP + "Content-Length: 100\r\n\r\n"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    String partial = "x".repeat(40);
    assertThrows(EOFException.class, () -> HttpIo.sendBody(out, in(partial), null, resp));
    assertEquals(partial, out.toString(StandardCharsets.ISO_8859_1));
  }

  @Test
  void untilCloseBodyEndsCleanlyAtEof() throws IOException {
    byte[] out = send(RESP + "Content-Type: text/plain\r\n\r\n", "hello");
    assertEquals("hello", new String(out, StandardCharsets.ISO_8859_1));
  }
}
