/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpInputStream;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Repeatable in-process performance smoke tests. Run with {@code ./gradlew test --tests
 * '*ProxyPerformanceBenchmarkTest'}.
 */
class ProxyPerformanceBenchmarkTest {

  private MockParentProxy parent;
  private ServerSocket clientListener;

  @AfterEach
  void tearDown() throws IOException {
    if (clientListener != null) clientListener.close();
    if (parent != null) parent.stop();
  }

  @Test
  void measuresKeepAliveAndBodyWorkloads() throws Exception {
    parent = new MockParentProxy();
    parent.start();
    clientListener = new ServerSocket();
    clientListener.bind(new InetSocketAddress("127.0.0.1", 0));

    val props = new JntlmProperties();
    props.setParents(List.of("127.0.0.1:" + parent.port()));
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setPassword("SecREt01");
    props.getDetect().setEnabled(false);
    val creds = new JntlmConfig().globalCredentials(props);
    val pool = new ConnectionPool();
    val manager = new ParentProxyManager(props, pool);
    val resolver = new NtlmFlagsResolver(manager, creds, props);
    val forwarder =
        new RequestForwarder(manager, pool, new ProxyAuthenticator(manager), creds, resolver);

    val body = "x".repeat(1024);
    parent.responseBody(body, false);
    val memoryBefore = usedMemory();
    val start = System.nanoTime();
    for (int i = 0; i < 10; i++)
      assertEquals(body, roundTrip(forwarder, "http://example.com/" + i));
    val elapsed = System.nanoTime() - start;

    parent.responseBody("y".repeat(1024 * 1024), false);
    assertEquals(1024 * 1024, roundTrip(forwarder, "http://example.com/large").length());
    pool.invalidateAll();

    parent.responseBody("chunk".repeat(256), true);
    assertEquals("chunk".repeat(256), roundTrip(forwarder, "http://example.com/chunked"));
    parent.rejectType1(0xa208b205L);
    props.getDetect().setEnabled(true);
    val detectedPool = new ConnectionPool();
    val detectedManager = new ParentProxyManager(props, detectedPool);
    val detectedCreds = new JntlmConfig().globalCredentials(props);
    val detectedResolver = new NtlmFlagsResolver(detectedManager, detectedCreds, props);
    val detectedForwarder =
        new RequestForwarder(
            detectedManager,
            detectedPool,
            new ProxyAuthenticator(detectedManager),
            detectedCreds,
            detectedResolver);
    assertEquals("chunk".repeat(256), roundTrip(detectedForwarder, "http://example.com/detect"));
    val failure = new AtomicReference<Throwable>();
    val concurrent = new ArrayList<Thread>();
    for (int i = 0; i < 4; i++) {
      int requestId = i;
      concurrent.add(
          Thread.ofVirtual()
              .start(() -> {
                try {
                  assertEquals(
                      "chunk".repeat(256),
                      roundTrip(detectedForwarder, "http://example.com/concurrent/" + requestId));
                } catch (Throwable t) {
                  failure.compareAndSet(null, t);
                }
              }));
    }
    for (val task : concurrent) task.join(2000);
    if (failure.get() != null)
      throw new AssertionError("concurrent benchmark request failed", failure.get());
    System.out.printf(
        "proxy benchmark: requests=13 elapsed_ms=%.2f used_memory_delta=%d pool_hits=%d "
            + "fresh_connections=%d%n",
        elapsed / 1_000_000.0,
        usedMemory() - memoryBefore,
        pool.poolHits(),
        pool.freshConnections());
  }

  /** Builds a forwarding stack against {@link #parent} with the given pool. */
  private RequestForwarder forwarder(JntlmProperties props, ConnectionPool pool) {
    val creds = new JntlmConfig().globalCredentials(props);
    val manager = new ParentProxyManager(props, pool);
    val resolver = new NtlmFlagsResolver(manager, creds, props);
    return new RequestForwarder(manager, pool, new ProxyAuthenticator(manager), creds, resolver);
  }

  private JntlmProperties startParent() throws IOException {
    parent = new MockParentProxy();
    parent.start();
    clientListener = new ServerSocket();
    clientListener.bind(new InetSocketAddress("127.0.0.1", 0), 128);
    val props = new JntlmProperties();
    props.setParents(List.of("127.0.0.1:" + parent.port()));
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setPassword("SecREt01");
    props.getDetect().setEnabled(false);
    return props;
  }

  /** Workload (a): many keep-alive requests over one client connection. */
  @Test
  void measuresKeepAliveOnOneClientConnection() throws Exception {
    val props = startParent();
    val pool = new ConnectionPool();
    val forwarder = forwarder(props, pool);
    val body = "k".repeat(512);
    parent.responseBody(body, false);
    val requests = 500;
    val client = new Socket();
    client.connect(clientListener.getLocalSocketAddress());
    client.setSoTimeout(10_000);
    val server = new Endpoint(clientListener.accept());
    val task =
        Thread.ofVirtual().start(() -> forwarder.forward(server, get("http://example.com/0")));
    val in = new BufferedInputStream(client.getInputStream());
    val out = client.getOutputStream();
    val start = System.nanoTime();
    assertEquals(body, readBody(in));
    for (int i = 1; i < requests; i++) {
      out.write(
          ("GET http://example.com/"
                  + i
                  + " HTTP/1.1\r\nHost: example.com\r\n"
                  + "Proxy-Connection: keep-alive\r\n\r\n")
              .getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      assertEquals(body, readBody(in));
    }
    val elapsed = System.nanoTime() - start;
    client.close();
    task.join(2000);
    assertEquals(1, parent.connectionsAccepted(), "one parent connection serves all requests");
    System.out.printf(
        "proxy benchmark keep-alive: requests=%d elapsed_ms=%.2f req_per_s=%.0f%n",
        requests, elapsed / 1e6, requests / (elapsed / 1e9));
  }

  /** Workload (b): 8 MiB echoed through a CONNECT tunnel. */
  @Test
  void measuresConnectTunnelThroughput() throws Exception {
    val props = startParent();
    parent.rawEcho(true);
    val forwarder = forwarder(props, new ConnectionPool());
    val client = new Socket();
    client.connect(clientListener.getLocalSocketAddress());
    client.setSoTimeout(30_000);
    val server = new Endpoint(clientListener.accept());
    val connect = HttpMessage.newRequest("CONNECT", "example.com:443", "HTTP/1.1");
    connect.setHost("example.com");
    connect.setPort(443);
    connect.getHeaders().add("Host", "example.com:443");
    val task = Thread.ofVirtual().start(() -> forwarder.forward(server, connect));
    val in = client.getInputStream();
    assertTrue(readLine(in).contains(" 200 "));
    while (!readLine(in).isEmpty()) Thread.onSpinWait();

    val data = new byte[8 * 1024 * 1024];
    new Random(3).nextBytes(data);
    val start = System.nanoTime();
    val writer =
        Thread.ofVirtual()
            .start(() -> {
              try {
                client.getOutputStream().write(data);
                client.getOutputStream().flush();
              } catch (IOException ignored) {
                // the reader's assertion reports the failure
              }
            });
    val echoed = in.readNBytes(data.length);
    val elapsed = System.nanoTime() - start;
    writer.join(5000);
    assertArrayEquals(data, echoed);
    client.close();
    task.join(2000);
    System.out.printf(
        "proxy benchmark tunnel: bytes=%d elapsed_ms=%.2f mb_per_s=%.1f%n",
        data.length, elapsed / 1e6, data.length / 1048576.0 / (elapsed / 1e9));
  }

  /** Workload (c): a burst of concurrent clients, then idle until the pool has drained. */
  @SuppressWarnings({"java:S2925", "BusyWait"})
  @Test
  void drainsPoolAfterBurstAndIdle() throws Exception {
    val props = startParent();
    props.getPool().setIdleTimeout(Duration.ofSeconds(1));
    val pool = new ConnectionPool(props.getPool());
    try (pool) {
      pool.start();
      val forwarder = forwarder(props, pool);
      val clients = 32;
      val failure = new AtomicReference<Throwable>();
      val gate = new CountDownLatch(1);
      val threads = new ArrayList<Thread>();
      for (int i = 0; i < clients; i++) {
        val url = "http://example.com/burst/" + i;
        threads.add(
            Thread.ofVirtual()
                .start(() -> {
                  try {
                    gate.await();
                    assertEquals("hello", roundTrip(forwarder, url));
                  } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                  }
                }));
      }
      val start = System.nanoTime();
      gate.countDown();
      for (val t : threads) t.join(10_000);
      val burst = System.nanoTime() - start;
      if (failure.get() != null) throw new AssertionError("burst request failed", failure.get());
      val pooledAfterBurst = pool.idleCount();

      val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
      while ((pool.idleCount() > 0 || parent.openConnections() > 0) && System.nanoTime() < deadline)
        Thread.sleep(50);
      val drained = System.nanoTime() - start;
      assertEquals(0, pool.idleCount(), "pool must drain after idle-timeout");
      assertEquals(0, parent.openConnections(), "no parent socket may stay open");
      System.out.printf(
          "proxy benchmark burst: clients=%d burst_ms=%.2f pooled_after_burst=%d evictions=%d "
              + "open_parent_sockets_after_idle=%d drain_ms=%.0f%n",
          clients,
          burst / 1e6,
          pooledAfterBurst,
          pool.evictions(),
          parent.openConnections(),
          drained / 1e6);
    }
  }

  /** Workload (d): header parsing, buffered line scanning versus the byte-by-byte loop. */
  @Test
  void measuresHeaderParsing() throws Exception {
    val sb = new StringBuilder("GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n");
    for (int i = 0; i < 29; i++)
      sb.append("X-Header-").append(i).append(": value-").repeat("v", 20).append("\r\n");
    val raw = sb.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
    val messages = 10_000;
    for (int warm = 0; warm < 2; warm++) {
      parse(raw, messages, true);
      parse(raw, messages, false);
    }
    val fast = parse(raw, messages, true);
    val bytewise = parse(raw, messages, false);
    System.out.printf(
        "proxy benchmark header-parse: messages=%d headers=30 http_input_stream_ms=%.2f "
            + "buffered_input_stream_ms=%.2f%n",
        messages, fast / 1e6, bytewise / 1e6);
  }

  @SuppressWarnings("SameParameterValue")
  private static long parse(byte[] raw, int messages, boolean fast) throws IOException {
    val start = System.nanoTime();
    for (int i = 0; i < messages; i++) {
      val bytes = new ByteArrayInputStream(raw);
      InputStream in = fast ? new HttpInputStream(bytes) : new BufferedInputStream(bytes);
      assertEquals(30, HttpIo.recvHeaders(in).getHeaders().size());
    }
    return System.nanoTime() - start;
  }

  @SuppressWarnings("SameParameterValue")
  private static HttpMessage get(String url) {
    val request = HttpMessage.newRequest("GET", url, "HTTP/1.1");
    request.setHost("example.com");
    request.setPort(80);
    request.getHeaders().add("Host", "example.com");
    request.getHeaders().add("Proxy-Connection", "keep-alive");
    return request;
  }

  private String roundTrip(RequestForwarder forwarder, String url) throws Exception {
    val client = new Socket();
    final Endpoint server;
    // Pair each client socket with its own accepted socket when called concurrently.
    synchronized (this) {
      client.connect(clientListener.getLocalSocketAddress());
      server = new Endpoint(clientListener.accept());
    }
    val request = HttpMessage.newRequest("GET", url, "HTTP/1.1");
    request.setHost("example.com");
    request.setPort(80);
    request.getHeaders().add("Host", "example.com");
    request.getHeaders().add("Proxy-Connection", "keep-alive");
    val task = Thread.ofVirtual().start(() -> forwarder.forward(server, request));
    val body = readBody(client.getInputStream());
    client.close();
    task.join(2000);
    return body;
  }

  private static String readBody(InputStream in) throws IOException {
    String status = readLine(in);
    assertEquals(200, Integer.parseInt(status.split(" ")[1]));
    int length = 0;
    String line;
    boolean chunked = false;
    while (!(line = readLine(in)).isEmpty()) {
      if (line.regionMatches(true, 0, "Content-Length:", 0, 15))
        length = Integer.parseInt(line.substring(15).trim());
      if (line.regionMatches(true, 0, "Transfer-Encoding:", 0, 18)
          && line.toLowerCase().contains("chunked")) chunked = true;
    }
    if (!chunked) return new String(in.readNBytes(length), StandardCharsets.ISO_8859_1);
    val result = new StringBuilder();
    while (true) {
      int size = Integer.parseInt(readLine(in).trim(), 16);
      if (size == 0) {
        readLine(in);
        return result.toString();
      }
      result.append(new String(in.readNBytes(size), StandardCharsets.ISO_8859_1));
      readLine(in);
    }
  }

  private static String readLine(InputStream in) throws IOException {
    val result = new StringBuilder();
    int c;
    while ((c = in.read()) != -1 && c != '\n') if (c != '\r') result.append((char) c);
    return result.toString();
  }

  private static long usedMemory() {
    val runtime = Runtime.getRuntime();
    return runtime.totalMemory() - runtime.freeMemory();
  }
}
