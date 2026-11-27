/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.server.ClientAuthenticator;
import net.domax.jntlm.server.ClientConnectionHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * End-to-end tests of optional client BASIC authentication: a real {@link ClientConnectionHandler}
 * in front of the real forwarding stack and an in-JVM {@link MockParentProxy}.
 */
class ClientAuthIntegrationTest {

  private static final String PASSWORD = "s3cret";

  private MockParentProxy parent;
  private JntlmProperties props;
  private RequestForwarder forwarder;
  private ClientAuthenticator clientAuth;
  private ServerSocket clientListener;
  private final List<Thread> handlers = new ArrayList<>();

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
    props.getDetect().setEnabled(false);

    val user = new JntlmProperties.User();
    user.setUsername("alice");
    user.setPassword(PASSWORD);
    props.getClientAuth().setUsers(new ArrayList<>(List.of(user)));
    props.getClientAuth().setEnabled(true);
    wire();

    clientListener = new ServerSocket();
    clientListener.bind(new InetSocketAddress("127.0.0.1", 0));
  }

  private void wire() {
    val config = new JntlmConfig();
    val creds = config.globalCredentials(props);
    val pool = new ConnectionPool();
    val manager = new ParentProxyManager(props, pool);
    val auth = new ProxyAuthenticator(manager);
    val resolver = new NtlmFlagsResolver(manager, creds, props);
    forwarder = new RequestForwarder(manager, pool, auth, creds, resolver);
    clientAuth = config.clientAuthenticator(props);
  }

  @AfterEach
  void tearDown() throws Exception {
    clientListener.close();
    parent.stop();
    for (val t : handlers) t.join(2000);
  }

  // ---------------------------------------------------------------- disabled

  @Test
  void disabledForwardsWithoutCredentials() throws Exception {
    props.getClientAuth().setEnabled(false);
    wire();
    try (val c = connect()) {
      send(c, get("http://example.com/", null));
      val r = readResponse(c.getInputStream());
      assertEquals(200, r.status());
      assertEquals("hello", r.body());
    }
  }

  // ---------------------------------------------------------------- rejection

  @Test
  void missingCredentialsChallengedAndClosed() throws Exception {
    try (val c = connect()) {
      send(c, get("http://example.com/", null));
      assertChallengedAndClosed(c, "jntlm");
    }
    assertEquals(0, parent.connectionsAccepted(), "parent must not be contacted");
  }

  @Test
  void wrongPasswordChallengedAndClosed() throws Exception {
    try (val c = connect()) {
      send(c, get("http://example.com/", basic("alice:wrong")));
      assertChallengedAndClosed(c, "jntlm");
    }
    assertEquals(0, parent.connectionsAccepted());
  }

  @Test
  void customRealmIsAdvertised() throws Exception {
    props.getClientAuth().setRealm("Corp Gateway");
    wire();
    try (val c = connect()) {
      send(c, get("http://example.com/", null));
      assertChallengedAndClosed(c, "Corp Gateway");
    }
  }

  @Test
  void connectWithoutCredentialsChallengedWithoutTunnel() throws Exception {
    try (val c = connect()) {
      send(c, connectRequest(null));
      assertChallengedAndClosed(c, "jntlm");
    }
    assertEquals(0, parent.connectionsAccepted(), "no tunnel may be established");
  }

  // ---------------------------------------------------------------- acceptance

  @Test
  void validCredentialsForwardedAndNotLeakedToParent() throws Exception {
    try (val c = connect()) {
      send(c, get("http://example.com/a", basic("alice:" + PASSWORD)));
      val r = readResponse(c.getInputStream());
      assertEquals(200, r.status());
      assertEquals("hello", r.body());
    }
    assertFalse(parent.proxyAuthorizations().isEmpty(), "parent must see jntlm's NTLM header");
    assertTrue(
        parent.proxyAuthorizations().stream().allMatch(h -> h.startsWith("NTLM ")),
        "client BASIC credentials must never reach the parent: " + parent.proxyAuthorizations());
  }

  @Test
  void keepAliveRequestsAfterAuthenticationAreNotRechecked() throws Exception {
    try (val c = connect()) {
      val in = c.getInputStream();
      send(c, get("http://example.com/a", basic("alice:" + PASSWORD)));
      assertEquals(200, readResponse(in).status());
      send(c, get("http://example.com/b", null));
      val r2 = readResponse(in);
      assertEquals(200, r2.status());
      assertEquals("hello", r2.body());
    }
  }

  @Test
  void newConnectionMustAuthenticateAgain() throws Exception {
    try (val c = connect()) {
      send(c, get("http://example.com/a", basic("alice:" + PASSWORD)));
      assertEquals(200, readResponse(c.getInputStream()).status());
    }
    try (val c = connect()) {
      send(c, get("http://example.com/b", null));
      assertChallengedAndClosed(c, "jntlm");
    }
  }

  @Test
  void authenticatedConnectTunnels() throws Exception {
    try (val c = connect()) {
      val in = c.getInputStream();
      send(c, connectRequest(basic("alice:" + PASSWORD)));
      val status = readLine(in);
      assertTrue(status.contains(" 200"), "CONNECT should establish the tunnel: " + status);
      //noinspection StatementWithEmptyBody
      while (!readLine(in).isEmpty()) {
        // skip response headers
      }
      val out = c.getOutputStream();
      out.write("ping".getBytes(ISO_8859_1));
      out.flush();
      val buf = new byte[4];
      val n = in.read(buf);
      assertEquals("PING", new String(buf, 0, n, ISO_8859_1));
    }
  }

  // ---------------------------------------------------------------- logging

  @Test
  void failedAttemptLogsAddressAndUserButNoSecrets() throws Exception {
    val logger = (Logger) LoggerFactory.getLogger(ClientConnectionHandler.class);
    val appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    try {
      val header = basic("alice:wrong");
      try (val c = connect()) {
        send(c, get("http://example.com/", header));
        assertChallengedAndClosed(c, "jntlm");
      }
      for (val t : handlers) t.join(2000);

      val warns =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .map(ILoggingEvent::getFormattedMessage)
              .toList();
      assertEquals(1, warns.size(), warns.toString());
      val msg = warns.getFirst();
      assertTrue(msg.contains("127.0.0.1"), msg);
      assertTrue(msg.contains("alice"), msg);
      assertFalse(msg.contains("wrong"), msg);
      assertFalse(msg.contains(header.substring("Basic ".length())), msg);
      appender.list.forEach(
          e -> assertFalse(e.getFormattedMessage().contains("wrong"), e.getFormattedMessage()));
    } finally {
      logger.detachAppender(appender);
    }
  }

  // ---------------------------------------------------------------- helpers

  /** Opens a client socket and starts a {@link ClientConnectionHandler} for its server side. */
  private Socket connect() throws IOException {
    val c = new Socket();
    c.connect(clientListener.getLocalSocketAddress());
    c.setSoTimeout(5000);
    val ep = new Endpoint(clientListener.accept());
    handlers.add(Thread.ofVirtual().start(new ClientConnectionHandler(ep, forwarder, clientAuth)));
    return c;
  }

  private static String basic(String userPass) {
    return "Basic " + Base64.getEncoder().encodeToString(userPass.getBytes(UTF_8));
  }

  private static String get(String url, String proxyAuthorization) {
    return "GET "
        + url
        + " HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n"
        + (proxyAuthorization == null ? "" : "Proxy-Authorization: " + proxyAuthorization + "\r\n")
        + "\r\n";
  }

  private static String connectRequest(String proxyAuthorization) {
    return "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
        + (proxyAuthorization == null ? "" : "Proxy-Authorization: " + proxyAuthorization + "\r\n")
        + "\r\n";
  }

  private static void send(Socket c, String raw) throws IOException {
    OutputStream out = c.getOutputStream();
    out.write(raw.getBytes(ISO_8859_1));
    out.flush();
  }

  private static void assertChallengedAndClosed(Socket c, String realm) throws IOException {
    val in = c.getInputStream();
    val r = readResponse(in);
    assertEquals(407, r.status());
    assertEquals("Basic realm=\"" + realm + "\"", r.headers().get("proxy-authenticate"));
    assertEquals("close", r.headers().get("connection"));
    assertEquals(-1, in.read(), "connection must be closed after the 407");
  }

  private static String readLine(InputStream in) throws IOException {
    val sb = new StringBuilder();
    int ch;
    while ((ch = in.read()) != -1 && ch != '\n') if (ch != '\r') sb.append((char) ch);
    return sb.toString();
  }

  private static Response readResponse(InputStream in) throws IOException {
    val status = Integer.parseInt(readLine(in).split(" ")[1]);
    val headers = new LinkedHashMap<String, String>();
    String line;
    while (!(line = readLine(in)).isEmpty()) {
      int colon = line.indexOf(':');
      if (colon > 0)
        headers.put(
            line.substring(0, colon).trim().toLowerCase(), line.substring(colon + 1).trim());
    }
    val len = Integer.parseInt(headers.getOrDefault("content-length", "0"));
    return new Response(status, headers, new String(in.readNBytes(len), ISO_8859_1));
  }

  private record Response(int status, Map<String, String> headers, String body) {}
}
