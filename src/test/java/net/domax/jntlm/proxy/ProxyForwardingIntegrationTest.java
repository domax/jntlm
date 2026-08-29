/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.ntlm.Credentials;
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
  private RequestForwarder forwarder;
  private ServerSocket clientListener;

  @BeforeEach
  void setUp() throws IOException {
    parent = new MockParentProxy();
    parent.start();

    JntlmProperties props = new JntlmProperties();
    props.setParents(List.of("127.0.0.1:" + parent.port()));
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setDomain("TESTDOMAIN");
    props.getCredentials().setPassword("SecREt01");
    props.getCredentials().setWorkstation("WS");

    Credentials creds = new JntlmConfig().globalCredentials(props);
    ConnectionPool pool = new ConnectionPool();
    ParentProxyManager manager = new ParentProxyManager(props, pool);
    ProxyAuthenticator auth = new ProxyAuthenticator(manager);
    forwarder = new RequestForwarder(manager, pool, auth, creds);

    clientListener = new ServerSocket();
    clientListener.bind(new InetSocketAddress("127.0.0.1", 0));
  }

  @AfterEach
  void tearDown() throws IOException {
    clientListener.close();
    parent.stop();
  }

  @Test
  void completesNtlmHandshakeAndRelaysResponse() throws Exception {
    Socket testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    Socket clientSide = clientListener.accept();
    Endpoint clientEp = new Endpoint(clientSide);

    HttpMessage first = get("http://example.com/page");
    Thread t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, first));

    MockResponse r = readResponse(testClient.getInputStream());
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
    Socket testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    Socket clientSide = clientListener.accept();
    Endpoint clientEp = new Endpoint(clientSide);

    HttpMessage first = get("http://example.com/a");
    Thread t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, first));

    InputStream in = testClient.getInputStream();
    OutputStream out = testClient.getOutputStream();

    MockResponse r1 = readResponse(in);

    // Second request sent as raw HTTP over the same client socket.
    out.write(
        ("GET http://example.com/b HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Proxy-Connection: keep-alive\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
    MockResponse r2 = readResponse(in);

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
    Socket testClient = new Socket();
    testClient.connect(clientListener.getLocalSocketAddress());
    Socket clientSide = clientListener.accept();
    Endpoint clientEp = new Endpoint(clientSide);

    HttpMessage connect = HttpMessage.newRequest("CONNECT", "example.com:443", "HTTP/1.1");
    connect.setHost("example.com");
    connect.setPort(443);
    connect.getHeaders().add("Host", "example.com:443");

    Thread t = Thread.ofVirtual().start(() -> forwarder.forward(clientEp, connect));

    InputStream in = testClient.getInputStream();
    OutputStream out = testClient.getOutputStream();

    String statusLine = readLine(in);
    assertTrue(statusLine.contains("200"), "CONNECT should establish the tunnel: " + statusLine);
    // consume remaining response headers
    while (!readLine(in).isEmpty()) {
      // skip
    }

    // The mock relays tunneled bytes back upper-cased, proving the client's bytes reached the
    // parent and the parent's response reached the client (a self-echoing tunnel would fail).
    out.write("ping".getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
    byte[] buf = new byte[4];
    int n = in.read(buf);
    assertEquals("PING", new String(buf, 0, n, StandardCharsets.ISO_8859_1));

    testClient.close();
    t.join(2000);
  }

  // --- helpers ---

  private static HttpMessage get(String url) {
    HttpMessage req = HttpMessage.newRequest("GET", url, "HTTP/1.1");
    req.setHost("example.com");
    req.getHeaders().add("Host", "example.com");
    req.getHeaders().add("Proxy-Connection", "keep-alive");
    return req;
  }

  private static String readLine(InputStream in) throws IOException {
    StringBuilder sb = new StringBuilder();
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
    String statusLine = readLine(in);
    int status = Integer.parseInt(statusLine.split(" ")[1]);
    int contentLength = 0;
    String line;
    while (!(line = readLine(in)).isEmpty()) {
      int colon = line.indexOf(':');
      if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
        contentLength = Integer.parseInt(line.substring(colon + 1).trim());
      }
    }
    byte[] body = in.readNBytes(contentLength);
    return new MockResponse(status, new String(body, StandardCharsets.ISO_8859_1));
  }

  private record MockResponse(int status, String body) {}

  /** Minimal parent proxy that demands NTLM once per connection then serves 200s. */
  private static final class MockParentProxy {
    private ServerSocket serverSocket;
    private volatile boolean running;
    private final AtomicInteger challenges = new AtomicInteger();
    private final AtomicInteger connections = new AtomicInteger();

    void start() throws IOException {
      serverSocket = new ServerSocket();
      serverSocket.bind(new InetSocketAddress("127.0.0.1", 0));
      running = true;
      Thread.ofVirtual().start(this::acceptLoop);
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    int challengesSent() {
      return challenges.get();
    }

    int connectionsAccepted() {
      return connections.get();
    }

    void stop() {
      running = false;
      try {
        serverSocket.close();
      } catch (IOException ignored) {
        // ignore
      }
    }

    private void acceptLoop() {
      while (running) {
        try {
          Socket socket = serverSocket.accept();
          connections.incrementAndGet();
          Thread.ofVirtual().start(() -> handle(socket));
        } catch (IOException e) {
          return;
        }
      }
    }

    private void handle(Socket socket) {
      try (socket) {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        boolean challenged = false;
        while (true) {
          Request req = readRequest(in);
          if (req == null) {
            return;
          }
          if (!challenged) {
            challenged = true;
            challenges.incrementAndGet();
            sendChallenge(out);
          } else if ("CONNECT".equals(req.method)) {
            sendConnectEstablished(out);
            echo(in, out);
            return;
          } else {
            sendOk(out);
          }
        }
      } catch (IOException ignored) {
        // connection ended
      }
    }

    private static Request readRequest(InputStream in) throws IOException {
      String requestLine = readLineRaw(in);
      if (requestLine == null || requestLine.isEmpty()) {
        return null;
      }
      String[] parts = requestLine.split(" ");
      String method = parts[0];
      int contentLength = 0;
      String line;
      while ((line = readLineRaw(in)) != null && !line.isEmpty()) {
        int colon = line.indexOf(':');
        if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
          contentLength = Integer.parseInt(line.substring(colon + 1).trim());
        }
      }
      if (contentLength > 0) {
        in.readNBytes(contentLength);
      }
      return new Request(method);
    }

    private static String readLineRaw(InputStream in) throws IOException {
      StringBuilder sb = new StringBuilder();
      int c;
      boolean any = false;
      while ((c = in.read()) != -1) {
        any = true;
        if (c == '\n') {
          break;
        }
        if (c != '\r') {
          sb.append((char) c);
        }
      }
      if (!any && sb.isEmpty()) {
        return null;
      }
      return sb.toString();
    }

    private static void sendChallenge(OutputStream out) throws IOException {
      byte[] challenge = new byte[52];
      System.arraycopy("NTLMSSP\0".getBytes(StandardCharsets.ISO_8859_1), 0, challenge, 0, 8);
      putU32(challenge, 8, 2);
      putU32(challenge, 20, 0x00000200);
      for (int i = 0; i < 8; i++) {
        challenge[24 + i] = (byte) (0x11 * (i + 1));
      }
      putU16(challenge, 44, 48);
      putU16(challenge, 48, 0);
      putU16(challenge, 50, 0);
      String b64 = Base64.getEncoder().encodeToString(challenge);
      String resp =
          "HTTP/1.1 407 Proxy Authentication Required\r\n"
              + "Proxy-Authenticate: NTLM "
              + b64
              + "\r\n"
              + "Proxy-Connection: keep-alive\r\n"
              + "Connection: keep-alive\r\n"
              + "Content-Length: 0\r\n\r\n";
      out.write(resp.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
    }

    private static void sendOk(OutputStream out) throws IOException {
      String body = "hello";
      String resp =
          "HTTP/1.1 200 OK\r\n"
              + "Content-Type: text/plain\r\n"
              + "Content-Length: "
              + body.length()
              + "\r\n"
              + "Proxy-Connection: keep-alive\r\n"
              + "Connection: keep-alive\r\n\r\n"
              + body;
      out.write(resp.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
    }

    @SuppressWarnings("java:S6126")
    private static void sendConnectEstablished(OutputStream out) throws IOException {
      String resp = "HTTP/1.1 200 Connection established\r\nProxy-Connection: keep-alive\r\n\r\n";
      out.write(resp.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
    }

    /**
     * Relays tunnelled bytes back to the caller, upper-casing each byte. The transform lets the
     * integration test distinguish a genuine client&harr;parent relay from a proxy that merely
     * echoes the client's own bytes back to it (which a mis-wired tunnel would do).
     */
    private static void echo(InputStream in, OutputStream out) throws IOException {
      byte[] buf = new byte[1024];
      int n;
      while ((n = in.read(buf)) != -1) {
        for (int i = 0; i < n; i++) {
          buf[i] = (byte) Character.toUpperCase(buf[i] & 0xff);
        }
        out.write(buf, 0, n);
        out.flush();
      }
    }

    private record Request(String method) {}

    private static void putU16(byte[] buf, int off, int val) {
      buf[off] = (byte) (val & 0xff);
      buf[off + 1] = (byte) ((val >>> 8) & 0xff);
    }

    private static void putU32(byte[] buf, int off, long val) {
      buf[off] = (byte) (val & 0xff);
      buf[off + 1] = (byte) ((val >>> 8) & 0xff);
      buf[off + 2] = (byte) ((val >>> 16) & 0xff);
      buf[off + 3] = (byte) ((val >>> 24) & 0xff);
    }
  }
}
