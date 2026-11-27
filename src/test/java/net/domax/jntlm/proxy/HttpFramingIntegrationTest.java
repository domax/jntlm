/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.proxy.MockParentProxy.AfterRaw;
import net.domax.jntlm.server.ClientAuthenticator;
import net.domax.jntlm.server.ClientConnectionHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * End-to-end strict-framing tests ({@code specs/http-message-framing}, parent-auth failure from
 * {@code specs/ntlm-authentication}): raw client bytes go through {@link ClientConnectionHandler}
 * and {@link RequestForwarder} to a {@link MockParentProxy}.
 */
class HttpFramingIntegrationTest {

  private static final String KEEP = "Proxy-Connection: keep-alive\r\n";

  private MockParentProxy parent;
  private RequestForwarder forwarder;
  private ClientAuthenticator clientAuth;
  private ServerSocket clientListener;
  private final List<Thread> handlers = new CopyOnWriteArrayList<>();

  @BeforeEach
  void setUp() throws IOException {
    parent = new MockParentProxy();
    parent.start();

    val props = new JntlmProperties();
    props.setParents(List.of("127.0.0.1:" + parent.port()));
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setDomain("TESTDOMAIN");
    props.getCredentials().setPassword("SecREt01");
    props.getCredentials().setWorkstation("WS");
    props.getDetect().setEnabled(false);

    val creds = new JntlmConfig().globalCredentials(props);
    val pool = new ConnectionPool();
    val manager = new ParentProxyManager(props, pool);
    val resolver = new NtlmFlagsResolver(manager, creds, props);
    forwarder =
        new RequestForwarder(manager, pool, new ProxyAuthenticator(manager), creds, resolver);
    clientAuth = new JntlmConfig().clientAuthenticator(props);

    clientListener = new ServerSocket();
    clientListener.bind(new InetSocketAddress("127.0.0.1", 0));
  }

  @AfterEach
  void tearDown() throws Exception {
    clientListener.close();
    parent.stop();
    for (val t : handlers) t.join(2000);
  }

  // ---------------------------------------------------------------- malformed client requests

  @ParameterizedTest
  @ValueSource(
      strings = {
        "Content-Length : 5\r\n",
        "X-Broken\r\n",
        " folded\r\n",
        "Content-Length: -5\r\n",
        "Content-Length: abc\r\n",
        "Content-Length: 5\r\nContent-Length: 6\r\n",
        "Transfer-Encoding: chunked\r\nContent-Length: 10\r\n",
        "Transfer-Encoding: xchunked\r\n",
      })
  void malformedRequestIsRejectedWith400AndNothingForwarded(String badHeaders) throws Exception {
    try (val c = connect()) {
      send(c, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n" + badHeaders + "\r\n");
      val raw = readAll(c.getInputStream());
      assertTrue(raw.startsWith("HTTP/1.0 400 Bad Request\r\n"), raw);
      assertTrue(raw.contains("Connection: close\r\n"), raw);
    }
    awaitHandlers();
    assertEquals(0, parent.connectionsAccepted());
  }

  @Test
  void garbageStartLineIsRejectedWith400() throws Exception {
    try (val c = connect()) {
      send(c, "GARBAGE\r\n\r\n");
      assertTrue(readAll(c.getInputStream()).startsWith("HTTP/1.0 400 "));
    }
    awaitHandlers();
    assertEquals(0, parent.connectionsAccepted());
  }

  @Test
  void bareCrIsRejectedWith400() throws Exception {
    try (val c = connect()) {
      send(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-A: a\rb\r\n\r\n");
      assertTrue(readAll(c.getInputStream()).startsWith("HTTP/1.0 400 "));
    }
  }

  @Test
  void malformedKeepAliveRequestIsRejectedWith400() throws Exception {
    try (val c = connect()) {
      send(c, get("http://example.com/a"));
      val in = c.getInputStream();
      assertTrue(readHead(in).startsWith("HTTP/1.1 200 "));
      readExactly(in, "hello".length());
      send(c, "GET http://example.com/b HTTP/1.1\r\nHost: example.com\r\nBroken\r\n\r\n");
      assertTrue(readAll(in).startsWith("HTTP/1.0 400 "));
    }
    awaitHandlers();
    assertTrue(parent.received().stream().noneMatch(r -> r.url().endsWith("/b")));
  }

  @Test
  void cleanCloseWithoutBytesWritesNothing() throws Exception {
    try (val c = connect()) {
      c.shutdownOutput();
      assertEquals("", readAll(c.getInputStream()));
    }
  }

  // ---------------------------------------------------------------- malformed parent responses

  @Test
  void malformedParentHeaderIs502() throws Exception {
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding : chunked\r\n" + KEEP + "\r\n0\r\n\r\n",
        AfterRaw.KEEP);
    assertTrue(exchange(get("http://example.com/")).startsWith("HTTP/1.1 502 Bad Gateway\r\n"));
  }

  @Test
  void invalidParentContentLengthIs502() throws Exception {
    parent.rawResponse("HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n" + KEEP + "\r\n", AfterRaw.KEEP);
    assertTrue(exchange(get("http://example.com/")).startsWith("HTTP/1.1 502 "));
  }

  @Test
  void invalidNtlmChallengeIs502AndParentClosed() throws Exception {
    parent.challengeHeader("NTLM AAAA");
    assertTrue(exchange(get("http://example.com/")).startsWith("HTTP/1.1 502 "));
    awaitHandlers();
    // The rejected connection is closed: the next request needs a fresh parent connection.
    exchange(get("http://example.com/"));
    assertEquals(2, parent.connectionsAccepted());
  }

  // ---------------------------------------------------------------- framing rules end-to-end

  @Test
  void responseWithTeAndClIsRelayedChunkedAndNotReused() throws Exception {
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n"
            + KEEP
            + "Connection: keep-alive\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        AfterRaw.KEEP);
    val raw = exchange(get("http://example.com/"));
    assertTrue(raw.startsWith("HTTP/1.1 200 "), raw);
    assertFalse(raw.toLowerCase().contains("content-length"), raw);
    assertTrue(raw.contains("Connection: close\r\n"), raw);
    assertTrue(raw.endsWith("\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), raw);

    exchange(get("http://example.com/"));
    assertEquals(2, parent.connectionsAccepted());
  }

  @Test
  void getWithBodyIsForwardedAndConnectionStaysInSync() throws Exception {
    try (val c = connect()) {
      send(
          c,
          "GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n"
              + KEEP
              + "Content-Length: 4\r\n\r\nabcd");
      val in = c.getInputStream();
      assertTrue(readHead(in).startsWith("HTTP/1.1 200 "));
      readExactly(in, "hello".length());
      send(c, get("http://example.com/b"));
      assertTrue(readHead(in).startsWith("HTTP/1.1 200 "));
    }
    awaitHandlers();
    assertTrue(
        parent.received().stream().anyMatch(r -> r.url().endsWith("/a") && r.body().equals("abcd")),
        parent.received().toString());
    assertTrue(parent.received().stream().anyMatch(r -> r.url().endsWith("/b")));
  }

  @SuppressWarnings({"java:S6126", "TextBlockMigration"})
  @Test
  void duplicateIdenticalContentLengthIsForwardedOnce() throws Exception {
    exchange(
        "POST http://example.com/p HTTP/1.1\r\nHost: example.com\r\n"
            + "Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello");
    val last = parent.received().getLast();
    assertEquals("hello", last.body());
    assertEquals(
        1, last.headerLines().stream().filter(h -> h.startsWith("Content-Length")).count());
  }

  @Test
  void parentClosingMidBodyClosesClientAndIsNotReused() throws Exception {
    val partial = "x".repeat(40);
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n" + KEEP + "\r\n" + partial, AfterRaw.CLOSE);
    val raw = exchange(get("http://example.com/"));
    assertTrue(raw.endsWith("\r\n\r\n" + partial), raw);

    exchange(get("http://example.com/"));
    assertEquals(2, parent.connectionsAccepted());
  }

  @Test
  void unframedResponseIsRelayedButNotPooled() throws Exception {
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + KEEP + "\r\nhello", AfterRaw.CLOSE);
    val raw = exchange(get("http://example.com/"));
    assertTrue(raw.endsWith("\r\n\r\nhello"), raw);

    exchange(get("http://example.com/"));
    assertEquals(2, parent.connectionsAccepted());
  }

  @Test
  void framedKeepAliveResponseIsPooled() throws Exception {
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nProxy-Connection: Keep-Alive, Upgrade\r\n\r\nok",
        AfterRaw.KEEP);
    assertTrue(exchange(get("http://example.com/")).endsWith("\r\n\r\nok"));
    assertTrue(exchange(get("http://example.com/")).endsWith("\r\n\r\nok"));
    assertEquals(1, parent.connectionsAccepted());
  }

  @Test
  void nonKeepAliveTokenIsNotPersistent() throws Exception {
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nProxy-Connection: not-keep-alive\r\n\r\nok",
        AfterRaw.KEEP);
    exchange(get("http://example.com/"));
    exchange(get("http://example.com/"));
    assertEquals(2, parent.connectionsAccepted());
  }

  @Test
  void repeatedIdenticalResponseHeadersArePreserved() throws Exception {
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: a=1\r\nContent-Length: 0\r\n"
            + KEEP
            + "\r\n",
        AfterRaw.KEEP);
    val raw = exchange(get("http://example.com/"));
    assertTrue(raw.contains("Set-Cookie: a=1\r\nSet-Cookie: a=1\r\n"), raw);
  }

  // ---------------------------------------------------------------- helpers

  private Socket connect() throws IOException {
    val c = new Socket();
    c.connect(clientListener.getLocalSocketAddress());
    c.setSoTimeout(5000);
    val ep = new Endpoint(clientListener.accept());
    handlers.add(Thread.ofVirtual().start(new ClientConnectionHandler(ep, forwarder, clientAuth)));
    return c;
  }

  private void awaitHandlers() throws InterruptedException {
    for (val t : handlers) t.join(5000);
  }

  /**
   * Sends one request on a new client connection, half-closes it, reads everything until the proxy
   * closes, then waits for the handler to finish (so pooling has happened).
   */
  private String exchange(String raw) throws Exception {
    try (val c = connect()) {
      send(c, raw);
      c.shutdownOutput();
      return readAll(c.getInputStream());
    } finally {
      awaitHandlers();
    }
  }

  private static String get(String url) {
    return "GET " + url + " HTTP/1.1\r\nHost: example.com\r\n" + KEEP + "\r\n";
  }

  private static void send(Socket c, String raw) throws IOException {
    c.getOutputStream().write(raw.getBytes(ISO_8859_1));
    c.getOutputStream().flush();
  }

  private static String readAll(InputStream in) throws IOException {
    return new String(in.readAllBytes(), ISO_8859_1);
  }

  /** Reads a response head (through the blank line). */
  private static String readHead(InputStream in) throws IOException {
    val buf = new ByteArrayOutputStream();
    int c;
    while ((c = in.read()) != -1) {
      buf.write(c);
      val s = buf.toString(ISO_8859_1);
      if (s.endsWith("\r\n\r\n")) return s;
    }
    return buf.toString(ISO_8859_1);
  }

  @SuppressWarnings("UnusedReturnValue")
  private static String readExactly(InputStream in, int n) throws IOException {
    return new String(in.readNBytes(n), ISO_8859_1);
  }
}
