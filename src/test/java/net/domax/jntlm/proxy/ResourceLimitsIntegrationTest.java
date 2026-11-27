/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpLimits;
import net.domax.jntlm.proxy.MockParentProxy.AfterRaw;
import net.domax.jntlm.server.ProxyServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.util.unit.DataSize;

/**
 * End-to-end tests for {@code jntlm.limits.*} ({@code specs/resource-limits}) against a real {@link
 * ProxyServer} bound to an ephemeral port and a {@link MockParentProxy}.
 */
@SuppressWarnings("java:S5778")
class ResourceLimitsIntegrationTest {

  private static final String KEEP = "Proxy-Connection: keep-alive\r\n";

  private MockParentProxy parent;
  private ProxyServer server;
  private final List<Socket> sockets = new ArrayList<>();

  @BeforeEach
  void setUp() throws IOException {
    parent = new MockParentProxy();
    parent.start();
  }

  @AfterEach
  void tearDown() {
    for (val s : sockets) {
      try {
        s.close();
      } catch (IOException ignored) {
        // ignore
      }
    }
    if (server != null) server.stop();
    parent.stop();
  }

  private void start(Consumer<JntlmProperties> customize) {
    val props = new JntlmProperties();
    props.setListenAddress("127.0.0.1");
    props.setListenPort(0);
    props.setParents(List.of("127.0.0.1:" + parent.port()));
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setDomain("TESTDOMAIN");
    props.getCredentials().setPassword("SecREt01");
    props.getCredentials().setWorkstation("WS");
    props.getDetect().setEnabled(false);
    customize.accept(props);

    val config = new JntlmConfig();
    val creds = config.globalCredentials(props);
    val limits = config.httpLimits(props);
    val pool = new ConnectionPool();
    val manager = new ParentProxyManager(props, pool);
    val resolver = new NtlmFlagsResolver(manager, creds, props);
    val forwarder =
        new RequestForwarder(
            manager, pool, new ProxyAuthenticator(manager, limits), creds, resolver, limits, props);
    server =
        new ProxyServer(
            props,
            forwarder,
            Executors.newVirtualThreadPerTaskExecutor(),
            config.clientAuthenticator(props));
    server.start();
  }

  // ---------------------------------------------------------------- header limits

  @Test
  void tooManyHeaderLinesIs431AndNothingForwarded() throws Exception {
    start(p -> {});
    val raw = exchange(get("http://example.com/", headers(257)));
    assertTrue(raw.startsWith("HTTP/1.0 431 Request Header Fields Too Large\r\n"), raw);
    assertTrue(raw.contains("Connection: close\r\n"), raw);
    assertEquals(0, parent.connectionsAccepted());
  }

  @Test
  void oversizedHeaderSectionIs431() throws Exception {
    start(p -> p.getLimits().setMaxHeaderSize(DataSize.ofKilobytes(1)));
    val raw = exchange(get("http://example.com/", "X-Big: " + "a".repeat(2000) + "\r\n"));
    assertTrue(raw.startsWith("HTTP/1.0 431 "), raw);
  }

  @Test
  void oversizedParentResponseHeadersAre502AndParentClosed() throws Exception {
    parent.rawResponse("HTTP/1.1 200 OK\r\n" + headers(300) + KEEP + "\r\n", AfterRaw.KEEP);
    start(p -> {});
    assertTrue(exchange(get("http://example.com/", "")).startsWith("HTTP/1.1 502 "));
    exchange(get("http://example.com/", ""));
    assertEquals(2, parent.connectionsAccepted());
  }

  @Test
  void headerLimitAppliesBeforeClientAuthentication() throws Exception {
    start(p -> {
      p.getClientAuth().setEnabled(true);
      val user = new JntlmProperties.User();
      user.setUsername("alice");
      user.setPassword("secret");
      p.getClientAuth().setUsers(List.of(user));
    });
    val raw = exchange(get("http://example.com/", headers(257)));
    assertTrue(raw.startsWith("HTTP/1.0 431 "), raw);
    assertEquals(0, parent.connectionsAccepted());
  }

  // ---------------------------------------------------------------- client idle timeout

  @Test
  void idleKeepAliveClientIsClosed() throws Exception {
    start(p -> p.getLimits().setClientIdleTimeout(Duration.ofSeconds(1)));
    val c = connect();
    send(c, get("http://example.com/", ""));
    val in = c.getInputStream();
    assertTrue(readHead(in).startsWith("HTTP/1.1 200 "));
    in.readNBytes("hello".length());

    val t0 = System.nanoTime();
    assertEquals(-1, in.read(), "idle client connection must be closed");
    val elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    assertTrue(elapsedMs >= 800 && elapsedMs < 4000, "closed after " + elapsedMs + " ms");
  }

  @SuppressWarnings("java:S2925")
  @Test
  void idleClientIsKeptWhenTimeoutDisabled() throws Exception {
    start(p -> p.getLimits().setClientIdleTimeout(Duration.ZERO));
    val c = connect();
    send(c, get("http://example.com/a", ""));
    val in = c.getInputStream();
    assertTrue(readHead(in).startsWith("HTTP/1.1 200 "));
    in.readNBytes("hello".length());

    Thread.sleep(1500);
    send(c, get("http://example.com/b", ""));
    assertTrue(readHead(in).startsWith("HTTP/1.1 200 "));
  }

  // ---------------------------------------------------------------- parent read timeout

  @Test
  void silentParentDuringAuthIs504() throws Exception {
    parent.noResponse(true);
    start(p -> p.getLimits().setParentReadTimeout(Duration.ofSeconds(1)));
    assertTrue(exchange(get("http://example.com/", "")).startsWith("HTTP/1.1 504 "));
  }

  @Test
  void silentParentAfterAuthIs504() throws Exception {
    parent.rawResponse("", AfterRaw.HANG);
    start(p -> p.getLimits().setParentReadTimeout(Duration.ofSeconds(1)));
    val raw = exchange(get("http://example.com/", ""));
    assertTrue(raw.startsWith("HTTP/1.1 504 Gateway Timeout\r\n"), raw);
  }

  @Test
  void parentStallingMidBodyClosesClientAndIsNotPooled() throws Exception {
    val partial = "x".repeat(40);
    parent.rawResponse(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n" + KEEP + "\r\n" + partial, AfterRaw.HANG);
    start(p -> p.getLimits().setParentReadTimeout(Duration.ofSeconds(1)));
    val raw = exchange(get("http://example.com/", ""));
    assertTrue(raw.endsWith("\r\n\r\n" + partial), raw);

    exchange(get("http://example.com/", ""));
    assertEquals(2, parent.connectionsAccepted());
  }

  // ---------------------------------------------------------------- tunnels

  @SuppressWarnings("java:S2925")
  @Test
  void idleTunnelSurvivesClientIdleTimeoutByDefault() throws Exception {
    start(p -> p.getLimits().setClientIdleTimeout(Duration.ofSeconds(1)));
    val c = openTunnel();
    Thread.sleep(2000);
    send(c, "ping");
    assertEquals("PING", new String(c.getInputStream().readNBytes(4), ISO_8859_1));
  }

  @Test
  void idleTunnelIsClosedWithTunnelIdleTimeout() throws Exception {
    start(p -> p.getLimits().setTunnelIdleTimeout(Duration.ofSeconds(1)));
    val c = openTunnel();
    send(c, "ping");
    assertEquals("PING", new String(c.getInputStream().readNBytes(4), ISO_8859_1));

    val t0 = System.nanoTime();
    assertEquals(-1, c.getInputStream().read(), "idle tunnel must be closed");
    val elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    assertTrue(elapsedMs >= 800 && elapsedMs < 4000, "closed after " + elapsedMs + " ms");
  }

  // ---------------------------------------------------------------- connection cap

  @SuppressWarnings("resource")
  @Test
  void connectionOverLimitGets503AndNoParentConnection() throws Exception {
    start(p -> p.getLimits().setMaxClientConnections(2));
    connect();
    connect();
    val third = connect();
    val raw = new String(third.getInputStream().readAllBytes(), ISO_8859_1);
    assertTrue(raw.startsWith("HTTP/1.0 503 Service Unavailable\r\n"), raw);
    assertTrue(raw.contains("Connection: close\r\n"), raw);
    assertEquals(0, parent.connectionsAccepted());
  }

  @SuppressWarnings({"java:S2925", "resource", "BusyWait"})
  @Test
  void capacityIsReleasedWhenAConnectionCloses() throws Exception {
    start(p -> p.getLimits().setMaxClientConnections(2));
    val first = connect();
    connect();
    first.close();

    String raw = "";
    for (int i = 0; i < 50 && !raw.startsWith("HTTP/1.1 200 "); i++) {
      raw = exchange(get("http://example.com/", ""));
      if (!raw.startsWith("HTTP/1.1 200 ")) Thread.sleep(100);
    }
    assertTrue(raw.startsWith("HTTP/1.1 200 "), raw);
  }

  // ---------------------------------------------------------------- configuration validation

  @Test
  void negativeTimeoutFailsNamingTheProperty() {
    val props = new JntlmProperties();
    props.getLimits().setClientIdleTimeout(Duration.ofSeconds(-1));
    val e = assertThrows(IllegalStateException.class, () -> new JntlmConfig().httpLimits(props));
    assertTrue(e.getMessage().contains("jntlm.limits.client-idle-timeout"), e.getMessage());
  }

  @Test
  void invalidHeaderLimitsAndConnectionCapFail() {
    val zeroBytes = new JntlmProperties();
    zeroBytes.getLimits().setMaxHeaderSize(DataSize.ofBytes(0));
    assertTrue(
        assertThrows(IllegalStateException.class, () -> new JntlmConfig().httpLimits(zeroBytes))
            .getMessage()
            .contains("jntlm.limits.max-header-size"));

    val negativeCap = new JntlmProperties();
    negativeCap.getLimits().setMaxClientConnections(-1);
    assertTrue(
        assertThrows(IllegalStateException.class, () -> new JntlmConfig().httpLimits(negativeCap))
            .getMessage()
            .contains("jntlm.limits.max-client-connections"));
  }

  @Test
  void defaultsMatchDocumentation() {
    val props = new JntlmProperties();
    assertEquals(HttpLimits.DEFAULT, new JntlmConfig().httpLimits(props));
    val l = props.getLimits();
    assertEquals(Duration.ofSeconds(300), l.getClientIdleTimeout());
    assertEquals(Duration.ofSeconds(600), l.getParentReadTimeout());
    assertEquals(Duration.ZERO, l.getTunnelIdleTimeout());
    assertEquals(1024, l.getMaxClientConnections());
  }

  // ---------------------------------------------------------------- helpers

  private Socket connect() throws IOException {
    val c = new Socket("127.0.0.1", server.localPort());
    c.setSoTimeout(10_000);
    sockets.add(c);
    return c;
  }

  private Socket openTunnel() throws IOException {
    val c = connect();
    send(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
    val head = readHead(c.getInputStream());
    assertTrue(head.startsWith("HTTP/1.1 200 "), head);
    return c;
  }

  private String exchange(String raw) throws IOException {
    try (val c = connect()) {
      send(c, raw);
      c.shutdownOutput();
      return new String(c.getInputStream().readAllBytes(), ISO_8859_1);
    }
  }

  private static String get(String url, String extraHeaders) {
    return "GET " + url + " HTTP/1.1\r\nHost: example.com\r\n" + KEEP + extraHeaders + "\r\n";
  }

  private static String headers(int n) {
    val sb = new StringBuilder();
    for (int i = 0; i < n; i++) sb.append("X-H").append(i).append(": v\r\n");
    return sb.toString();
  }

  private static void send(Socket c, String raw) throws IOException {
    c.getOutputStream().write(raw.getBytes(ISO_8859_1));
    c.getOutputStream().flush();
  }

  private static String readHead(InputStream in) throws IOException {
    val buf = new ByteArrayOutputStream();
    int ch;
    while ((ch = in.read()) != -1) {
      buf.write(ch);
      if (buf.toString(ISO_8859_1).endsWith("\r\n\r\n")) break;
    }
    return buf.toString(ISO_8859_1);
  }
}
