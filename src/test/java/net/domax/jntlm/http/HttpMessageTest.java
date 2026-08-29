/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Tests for HTTP message parsing/serialisation, header handling and body-length rules. */
class HttpMessageTest {

  @Test
  void headersAreCaseInsensitiveMultiValued() {
    HttpHeaders h = new HttpHeaders();
    h.add("Content-Type", "text/html");
    h.add("Set-Cookie", "a=1");
    h.add("set-cookie", "b=2");
    assertEquals("text/html", h.getFirst("content-type"));
    assertEquals(2, h.all().stream().filter(x -> x.name().equalsIgnoreCase("Set-Cookie")).count());
  }

  @Test
  void modifyReplacesAndRemoveDeletes() {
    HttpHeaders h = new HttpHeaders();
    h.add("Connection", "close");
    h.modify("Connection", "keep-alive");
    assertEquals("keep-alive", h.getFirst("Connection"));
    h.remove("connection");
    assertFalse(h.contains("Connection"));
    assertNull(h.getFirst("Connection"));
  }

  @Test
  void containsTokenMatchesCommaSeparatedValues() {
    HttpHeaders h = new HttpHeaders();
    h.add("Connection", "Keep-Alive, TE");
    assertTrue(h.containsToken("Connection", "te"));
    assertTrue(h.containsToken("Connection", "keep-alive"));
    assertFalse(h.containsToken("Connection", "close"));
  }

  @Test
  void copyIsDeep() {
    HttpMessage req = HttpMessage.newRequest("GET", "http://host/p", "HTTP/1.1");
    req.getHeaders().add("X-Test", "1");
    HttpMessage clone = req.copy();
    clone.getHeaders().modify("X-Test", "2");
    clone.setMethod("POST");
    assertEquals("1", req.getHeaders().getFirst("X-Test"));
    assertEquals("GET", req.getMethod());
    assertEquals("2", clone.getHeaders().getFirst("X-Test"));
  }

  @Test
  void versionParsedFromProtocol() {
    assertEquals(11, HttpMessage.newRequest("GET", "/", "HTTP/1.1").getHttpVersion());
    assertEquals(10, HttpMessage.newRequest("GET", "/", "HTTP/1.0").getHttpVersion());
  }

  @SuppressWarnings("java:S6126")
  @Test
  void recvHeadersParsesRequestLineAndHeaders() throws Exception {
    String raw =
        "GET http://example.com/path HTTP/1.1\r\n"
            + "Host: example.com\r\n"
            + "Proxy-Connection: keep-alive\r\n\r\n";
    HttpMessage m =
        HttpIo.recvHeaders(new ByteArrayInputStream(raw.getBytes(StandardCharsets.ISO_8859_1)));
    assertNotNull(m);
    assertTrue(m.isRequest());
    assertEquals("GET", m.getMethod());
    assertEquals(11, m.getHttpVersion());
    assertEquals("example.com", m.getHeaders().getFirst("Host"));
  }

  @Test
  void headResponseHasNoBody() {
    HttpMessage req = HttpMessage.newRequest("HEAD", "http://x/", "HTTP/1.1");
    HttpMessage resp = HttpMessage.newResponse("HTTP/1.1", 200, "OK");
    resp.getHeaders().add("Content-Length", "100");
    assertEquals(0, HttpIo.httpHasBody(req, resp));
  }

  @Test
  void contentLengthBodyIsReported() {
    HttpMessage req = HttpMessage.newRequest("GET", "http://x/", "HTTP/1.1");
    HttpMessage resp = HttpMessage.newResponse("HTTP/1.1", 200, "OK");
    resp.getHeaders().add("Content-Length", "42");
    assertEquals(42, HttpIo.httpHasBody(req, resp));
  }

  @Test
  void sendHeadersRoundTrips() throws Exception {
    HttpMessage resp = HttpMessage.newResponse("HTTP/1.1", 200, "OK");
    resp.getHeaders().add("Content-Length", "0");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    HttpIo.sendHeaders(out, resp);
    String s = out.toString(StandardCharsets.ISO_8859_1);
    assertTrue(s.startsWith("HTTP/1.1 200 OK\r\n"), s);
    assertTrue(s.contains("Content-Length: 0\r\n"), s);
    assertTrue(s.endsWith("\r\n\r\n"), s);
  }
}
