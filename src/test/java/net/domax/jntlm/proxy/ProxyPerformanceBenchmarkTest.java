/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
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
              .start(
                  () -> {
                    try {
                      assertEquals(
                          "chunk".repeat(256),
                          roundTrip(
                              detectedForwarder, "http://example.com/concurrent/" + requestId));
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

  private String roundTrip(RequestForwarder forwarder, String url) throws Exception {
    val client = new Socket();
    client.connect(clientListener.getLocalSocketAddress());
    val server = new Endpoint(clientListener.accept());
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
