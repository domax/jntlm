/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-JVM parent proxy speaking the NTLM 407 handshake, for tests.
 *
 * <p>By default, it challenges the first request on every connection and serves {@code 200 hello}
 * (or a CONNECT tunnel that upper-cases relayed bytes) once a Type-3 arrives. It can be configured
 * to reject specific Type-1 flags (407 without a challenge), reject the Type-3 that follows
 * specific Type-1 flags, advertise custom Type-2 flags, or not require authentication at all.
 */
@SuppressWarnings({"UnusedReturnValue", "SameParameterValue"})
final class MockParentProxy {

  /** A request as received by the mock. {@code ntlmType} is 0 when no NTLM header was present. */
  record Received(String method, String url, int ntlmType, long type1Flags, String body) {}

  private ServerSocket serverSocket;
  private volatile boolean running;
  private final AtomicInteger challenges = new AtomicInteger();
  private final AtomicInteger connections = new AtomicInteger();
  private final List<Long> type1Flags = new CopyOnWriteArrayList<>();
  private final List<Received> received = new CopyOnWriteArrayList<>();

  private final Set<Long> rejectType1 = ConcurrentHashMap.newKeySet();
  private final Set<Long> rejectType3 = ConcurrentHashMap.newKeySet();
  private volatile long type2Flags = 0x00000200L;
  private volatile boolean requireAuth = true;
  private volatile long challengeDelayMs;

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

  /** Negotiate flags of every Type-1 message received, in order. */
  List<Long> type1Flags() {
    return type1Flags;
  }

  /** Every request received, in order. */
  List<Received> received() {
    return received;
  }

  /** Replies 407 without an NTLM challenge to Type-1 messages carrying any of these flags. */
  MockParentProxy rejectType1(long... flags) {
    for (long f : flags) rejectType1.add(f);
    return this;
  }

  /** Replies 407 to the Type-3 that follows a Type-1 carrying any of these flags. */
  MockParentProxy rejectType3(long... flags) {
    for (long f : flags) rejectType3.add(f);
    return this;
  }

  /** Sets the negotiate flags advertised in the Type-2 challenge. */
  MockParentProxy type2Flags(long flags) {
    this.type2Flags = flags;
    return this;
  }

  /** When {@code false}, every request is served without authentication. */
  MockParentProxy requireAuth(boolean requireAuth) {
    this.requireAuth = requireAuth;
    return this;
  }

  /** Delays every challenge (to widen race windows in concurrency tests). */
  MockParentProxy challengeDelayMs(long delayMs) {
    this.challengeDelayMs = delayMs;
    return this;
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

  @SuppressWarnings("java:S3776")
  private void handle(Socket socket) {
    try (socket) {
      InputStream in = socket.getInputStream();
      OutputStream out = socket.getOutputStream();
      boolean authenticated = false;
      long connFlags = -1;
      while (true) {
        Request req = readRequest(in);
        if (req == null) {
          return;
        }
        byte[] ntlm = ntlmBlob(req.proxyAuthorization);
        int type = ntlm == null || ntlm.length < 12 ? 0 : (int) u32(ntlm, 8);
        long flags = type == 1 && ntlm.length >= 16 ? u32(ntlm, 12) : -1;
        received.add(new Received(req.method, req.url, type, flags, req.body));

        if (!requireAuth || authenticated) {
          if (serve(req, in, out)) return;
          continue;
        }
        if (type == 0 || type == 1) {
          if (type == 1) type1Flags.add(flags);
          if (type == 1 && rejectType1.contains(flags)) {
            send407(out, null);
            continue;
          }
          connFlags = flags;
          challenges.incrementAndGet();
          if (challengeDelayMs > 0) sleep(challengeDelayMs);
          sendChallenge(out, type2Flags);
        } else if (type == 3) {
          if (rejectType3.contains(connFlags)) {
            send407(out, "NTLM");
            continue;
          }
          authenticated = true;
          if (serve(req, in, out)) return;
        } else {
          send407(out, null);
        }
      }
    } catch (IOException ignored) {
      // connection ended
    }
  }

  /** Serves an authorized request; returns {@code true} if the connection is finished. */
  private static boolean serve(Request req, InputStream in, OutputStream out) throws IOException {
    if ("CONNECT".equals(req.method)) {
      sendConnectEstablished(out);
      echo(in, out);
      return true;
    }
    sendOk(out);
    return false;
  }

  @SuppressWarnings("java:S2925")
  private static void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static byte[] ntlmBlob(String header) {
    if (header == null || !header.regionMatches(true, 0, "NTLM ", 0, 5)) return null;
    try {
      return Base64.getDecoder().decode(header.substring(5).trim());
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static Request readRequest(InputStream in) throws IOException {
    String requestLine = readLineRaw(in);
    if (requestLine == null || requestLine.isEmpty()) {
      return null;
    }
    String[] parts = requestLine.split(" ");
    String method = parts[0];
    String url = parts.length > 1 ? parts[1] : "";
    int contentLength = 0;
    String proxyAuth = null;
    String line;
    while ((line = readLineRaw(in)) != null && !line.isEmpty()) {
      int colon = line.indexOf(':');
      if (colon <= 0) continue;
      String name = line.substring(0, colon).trim();
      String value = line.substring(colon + 1).trim();
      if (name.equalsIgnoreCase("Content-Length")) contentLength = Integer.parseInt(value);
      else if (name.equalsIgnoreCase("Proxy-Authorization")) proxyAuth = value;
    }
    String body = "";
    if (contentLength > 0) {
      body = new String(in.readNBytes(contentLength), StandardCharsets.ISO_8859_1);
    }
    return new Request(method, url, proxyAuth, body);
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

  private static void sendChallenge(OutputStream out, long flags) throws IOException {
    byte[] challenge = new byte[52];
    System.arraycopy("NTLMSSP\0".getBytes(StandardCharsets.ISO_8859_1), 0, challenge, 0, 8);
    putU32(challenge, 8, 2);
    putU32(challenge, 20, flags);
    for (int i = 0; i < 8; i++) {
      challenge[24 + i] = (byte) (0x11 * (i + 1));
    }
    putU16(challenge, 44, 48);
    putU16(challenge, 48, 0);
    putU16(challenge, 50, 0);
    String b64 = Base64.getEncoder().encodeToString(challenge);
    send407(out, "NTLM " + b64);
  }

  private static void send407(OutputStream out, String proxyAuthenticate) throws IOException {
    String resp =
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
            + (proxyAuthenticate == null ? "" : "Proxy-Authenticate: " + proxyAuthenticate + "\r\n")
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
   * Relays tunnelled bytes back to the caller, upper-casing each byte. The transform lets tests
   * distinguish a genuine client&harr;parent relay from a proxy that merely echoes the client's own
   * bytes back to it (which a mis-wired tunnel would do).
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

  private record Request(String method, String url, String proxyAuthorization, String body) {}

  private static long u32(byte[] buf, int off) {
    return (buf[off] & 0xffL)
        | ((buf[off + 1] & 0xffL) << 8)
        | ((buf[off + 2] & 0xffL) << 16)
        | ((buf[off + 3] & 0xffL) << 24);
  }

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
