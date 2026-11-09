/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpMessage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * End-to-end tests for the forwarding engine against an in-JVM mock parent proxy that speaks the
 * NTLM 407 handshake. Exercises the full {@link RequestForwarder} + {@link ProxyAuthenticator} +
 * {@link ConnectionPool} + {@link ParentProxyManager} stack.
 */
class ProxyForwardingIntegrationTest {

  private MockParentProxy parent;
  private JntlmProperties props;
  private RequestForwarder forwarder;
  private ConnectionPool pool;
  private ServerSocket clientListener;

  @BeforeEach
  void setUp() throws IOException {
    parent = new MockParentProxy();
    parent.start();

    props = new JntlmProperties();
    props.setParents(List.of("127.0.0.1:" + parent.port()));
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setDomain("TESTDOMAIN");
    props.getCredentials().setPassword("SecREt01");
    props.getCredentials().setWorkstation("WS");
    // Forwarding tests below assert exact handshake counts; detection has its own tests.
    props.getDetect().setEnabled(false);
    wire();

    clientListener = new ServerSocket();
    clientListener.bind(new InetSocketAddress("127.0.0.1", 0));
  }

  /** (Re)builds the forwarding stack from {@link #props}. */
  private void wire() {
    val creds = new JntlmConfig().globalCredentials(props);
    pool = new ConnectionPool();
    val manager = new ParentProxyManager(props, pool);
    val auth = new ProxyAuthenticator(manager);
    val resolver = new NtlmFlagsResolver(manager, creds, props);
    forwarder = new RequestForwarder(manager, pool, auth, creds, resolver);
  }

  @AfterEach
  void tearDown() throws IOException {
    clientListener.close();
    parent.stop();
  }

  @Test
  void completesNtlmHandshakeAndRelaysResponse() throws Exception {
    val testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    val clientSide = clientListener.accept();
    val clientEp = new Endpoint(clientSide);

    val first = get("http://example.com/page");
    val t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, first));

    val r = readResponse(testClient.getInputStream());
    assertEquals(200, r.status());
    assertEquals("hello", r.body());
    assertEquals(1, parent.challengesSent(), "exactly one NTLM challenge expected");

    testClient.close();
    t.join(2000);
  }

  @SuppressWarnings({"java:S6126", "TextBlockMigration"})
  @Test
  void reusesAuthenticatedConnectionForSecondRequest() throws Exception {
    // Both requests travel over one client connection; forward()'s keep-alive loop serves the
    // second one on the already-authenticated parent connection (no fresh connect, no re-auth).
    val testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    val clientSide = clientListener.accept();
    val clientEp = new Endpoint(clientSide);

    val first = get("http://example.com/a");
    val t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, first));

    val in = testClient.getInputStream();
    val out = testClient.getOutputStream();

    val r1 = readResponse(in);

    // Second request sent as raw HTTP over the same client socket.
    out.write(
        ("GET http://example.com/b HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Proxy-Connection: keep-alive\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
    val r2 = readResponse(in);

    assertEquals(200, r1.status());
    assertEquals(200, r2.status());
    assertEquals("hello", r2.body());
    // Only the first request triggered a challenge; the second reused the same connection.
    assertEquals(
        1, parent.challengesSent(), "second request must reuse the authenticated connection");
    assertEquals(1, parent.connectionsAccepted(), "no new parent connection should be opened");

    testClient.close();
    t.join(2000);
  }

  @SuppressWarnings("StatementWithEmptyBody")
  @Test
  void tunnelsConnectRequests() throws Exception {
    val testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    val clientSide = clientListener.accept();
    val clientEp = new Endpoint(clientSide);

    val connect = HttpMessage.newRequest("CONNECT", "example.com:443", "HTTP/1.1");
    connect.setHost("example.com");
    connect.setPort(443);
    connect.getHeaders().add("Host", "example.com:443");

    val t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, connect));

    val in = testClient.getInputStream();
    val out = testClient.getOutputStream();

    val statusLine = readLine(in);
    assertTrue(statusLine.contains("200"), "CONNECT should establish the tunnel: " + statusLine);
    // consume remaining response headers
    while (!readLine(in).isEmpty()) {
      // skip
    }

    // The mock relays tunneled bytes back upper-cased, proving the client's bytes reached the
    // parent and the parent's response reached the client (a self-echoing tunnel would fail).
    out.write("ping".getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
    val buf = new byte[4];
    val n = in.read(buf);
    assertEquals("PING", new String(buf, 0, n, StandardCharsets.ISO_8859_1));

    testClient.close();
    t.join(2000);
  }

  @Test
  void detectsFlagsOnFirstRequestAndReusesThem() throws Exception {
    parent.rejectType1(0xa208b205L, 0x0008b205L);
    props.getDetect().setEnabled(true);
    wire();

    assertEquals(200, roundTrip(get("http://example.com/one")).status());
    // Two rejected probes, one accepted probe, then the real handshake with the detected flags.
    assertEquals(List.of(0xa208b205L, 0x0008b205L, 0x00088205L, 0x00088205L), parent.type1Flags());

    pool.invalidateAll(); // force a fresh parent connection for the next request
    val r = roundTrip(get("http://example.com/two"));
    assertEquals(200, r.status());
    assertEquals("hello", r.body());
    assertEquals(5, parent.type1Flags().size(), "no new probes expected");
    assertEquals(0x00088205L, parent.type1Flags().getLast());
  }

  @Test
  void postBodyForwardedOnceAfterLazyGetProbe() throws Exception {
    props.getDetect().setEnabled(true);
    wire();

    val body = "hello-body";
    val post = HttpMessage.newRequest("POST", "http://example.com/api", "HTTP/1.1");
    post.setHost("example.com");
    post.setPort(80);
    post.getHeaders().add("Host", "example.com");
    post.getHeaders().add("Proxy-Connection", "keep-alive");
    post.getHeaders().add("Content-Length", String.valueOf(body.length()));

    val testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    val clientEp = new Endpoint(clientListener.accept());
    testClient.getOutputStream().write(body.getBytes(StandardCharsets.ISO_8859_1));
    testClient.getOutputStream().flush();

    val t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, post));
    val r = readResponse(testClient.getInputStream());
    assertEquals(200, r.status());

    val received = parent.received();
    assertEquals("GET", received.getFirst().method(), "detection must probe with GET");
    assertEquals("http://example.com/api", received.getFirst().url());
    assertEquals(
        List.of(body),
        received.stream()
            .filter(x -> "POST".equals(x.method()) && !x.body().isEmpty())
            .map(MockParentProxy.Received::body)
            .toList(),
        "the POST body must reach the parent exactly once");

    testClient.close();
    t.join(2000);
  }

  /** Sends {@code request} over a new client connection and returns the parent's response. */
  private MockResponse roundTrip(HttpMessage request) throws Exception {
    val testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    val clientEp = new Endpoint(clientListener.accept());
    val t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, request));
    val r = readResponse(testClient.getInputStream());
    testClient.close();
    t.join(2000);
    return r;
  }

  // --- helpers ---

  private static HttpMessage get(String url) {
    val req = HttpMessage.newRequest("GET", url, "HTTP/1.1");
    req.setHost("example.com");
    req.getHeaders().add("Host", "example.com");
    req.getHeaders().add("Proxy-Connection", "keep-alive");
    return req;
  }

  private static String readLine(InputStream in) throws IOException {
    val sb = new StringBuilder();
    int c;
    while ((c = in.read()) != -1) {
      if (c == '\n') {
        break;
      }
      if (c != '\r') {
        sb.append((char) c);
      }
    }
    return sb.toString();
  }

  private static MockResponse readResponse(InputStream in) throws IOException {
    val statusLine = readLine(in);
    val status = Integer.parseInt(statusLine.split(" ")[1]);
    var contentLength = 0;
    String line;
    while (!(line = readLine(in)).isEmpty()) {
      int colon = line.indexOf(':');
      if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
        contentLength = Integer.parseInt(line.substring(colon + 1).trim());
      }
    }
    val body = in.readNBytes(contentLength);
    return new MockResponse(status, new String(body, StandardCharsets.ISO_8859_1));
  }

  private record MockResponse(int status, String body) {}
}
