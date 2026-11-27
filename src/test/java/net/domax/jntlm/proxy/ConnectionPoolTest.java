/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.ntlm.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("resource")
class ConnectionPoolTest {

  private static final Credentials CREDS = new Credentials();

  private ServerSocket listener;
  private final List<Socket> accepted = new ArrayList<>();
  private final AtomicLong clock = new AtomicLong();
  private ConnectionPool pool;

  @BeforeEach
  void setUp() throws IOException {
    listener = new ServerSocket(0, 256, InetAddress.getLoopbackAddress());
  }

  @AfterEach
  void tearDown() throws IOException {
    if (pool != null) pool.close();
    for (val s : accepted) s.close();
    listener.close();
  }

  private Endpoint endpoint() throws IOException {
    val socket = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
    accepted.add(listener.accept());
    return new Endpoint(socket);
  }

  @SuppressWarnings("UnusedReturnValue")
  private ConnectionPool pool(int maxIdle, Duration timeout) {
    pool = new ConnectionPool(maxIdle, timeout, clock::get);
    return pool;
  }

  @Test
  void reusesMostRecentlyAddedFirst() throws IOException {
    pool(8, Duration.ofSeconds(60));
    val a = endpoint();
    val b = endpoint();
    pool.add(a, CREDS);
    pool.add(b, CREDS);
    assertSame(b, pool.pop().endpoint());
    assertSame(a, pool.pop().endpoint());
    assertNull(pool.pop());
    assertEquals(2, pool.poolHits());
    assertEquals(0, pool.evictions());
  }

  @Test
  void capClosesOldestIdleEntry() throws IOException {
    pool(2, Duration.ofSeconds(60));
    val a = endpoint();
    val b = endpoint();
    val c = endpoint();
    pool.add(a, CREDS);
    pool.add(b, CREDS);
    pool.add(c, CREDS);
    assertTrue(a.socket().isClosed());
    assertFalse(b.socket().isClosed());
    assertFalse(c.socket().isClosed());
    assertEquals(2, pool.idleCount());
    assertEquals(1, pool.evictions());
  }

  @Test
  void maxIdleZeroClosesImmediately() throws IOException {
    pool(0, Duration.ofSeconds(60));
    val a = endpoint();
    pool.add(a, CREDS);
    assertTrue(a.socket().isClosed());
    assertEquals(0, pool.idleCount());
    assertNull(pool.pop());
  }

  @Test
  void expiredEntryIsSkippedAndClosedOnPop() throws IOException {
    pool(8, Duration.ofSeconds(60));
    val old = endpoint();
    pool.add(old, CREDS);
    clock.addAndGet(Duration.ofSeconds(30).toNanos());
    val fresh = endpoint();
    pool.add(fresh, CREDS);
    clock.addAndGet(Duration.ofSeconds(40).toNanos());
    // fresh is 40 s idle (alive), old is 70 s idle (expired)
    assertSame(fresh, pool.pop().endpoint());
    assertNull(pool.pop());
    assertTrue(old.socket().isClosed());
    assertEquals(1, pool.evictions());
    assertEquals(1, pool.poolHits());
    assertEquals(0, pool.idleCount());
  }

  @SuppressWarnings({"java:S2925", "BusyWait"})
  @Test
  void sweeperClosesExpiredEntriesWithoutTraffic() throws Exception {
    pool = new ConnectionPool(8, Duration.ofSeconds(1), System::nanoTime);
    pool.start();
    assertTrue(pool.isRunning());
    val a = endpoint();
    pool.add(a, CREDS);
    val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (pool.idleCount() > 0 && System.nanoTime() < deadline) Thread.sleep(50);
    assertEquals(0, pool.idleCount());
    assertTrue(a.socket().isClosed());
    assertEquals(1, pool.evictions());
    pool.close();
    assertFalse(pool.isRunning());
  }

  @Test
  void sweepKeepsFreshEntries() throws IOException {
    pool(8, Duration.ofSeconds(60));
    val old = endpoint();
    pool.add(old, CREDS);
    clock.addAndGet(Duration.ofSeconds(61).toNanos());
    val fresh = endpoint();
    pool.add(fresh, CREDS);
    pool.sweep();
    assertTrue(old.socket().isClosed());
    assertFalse(fresh.socket().isClosed());
    assertEquals(1, pool.idleCount());
  }

  @Test
  void closeStopsSweeperAndClosesIdleEntries() throws IOException {
    pool(8, Duration.ofSeconds(60));
    pool.start();
    val a = endpoint();
    pool.add(a, CREDS);
    pool.close();
    assertTrue(a.socket().isClosed());
    assertEquals(0, pool.idleCount());
    assertFalse(pool.isRunning());
  }

  @Test
  void concurrentAddPopSweepNeverLosesOrDoubleClosesEntries() throws Exception {
    pool(4, Duration.ofSeconds(60));
    val endpoints = new ArrayList<Endpoint>();
    for (int i = 0; i < 200; i++) endpoints.add(endpoint());
    val popped = ConcurrentHashMap.<Endpoint>newKeySet();
    val failure = new AtomicReference<Throwable>();
    val start = new CountDownLatch(1);
    val threads = new ArrayList<Thread>();
    for (int t = 0; t < 4; t++) {
      int offset = t * 50;
      threads.add(
          Thread.ofVirtual()
              .start(() -> {
                try {
                  start.await();
                  for (int i = 0; i < 50; i++) {
                    pool.add(endpoints.get(offset + i), CREDS);
                    val c = pool.pop();
                    if (c != null && !popped.add(c.endpoint()))
                      throw new AssertionError("popped twice");
                    if (i % 10 == 0) {
                      clock.addAndGet(Duration.ofSeconds(1).toNanos());
                      pool.sweep();
                    }
                  }
                } catch (Throwable e) {
                  failure.compareAndSet(null, e);
                }
              }));
    }
    start.countDown();
    for (val t : threads) t.join(10_000);
    if (failure.get() != null) throw new AssertionError(failure.get());
    val hitsBeforeDrain = pool.poolHits();
    val remaining = Set.copyOf(drain());
    // Every endpoint is accounted for exactly once: popped (open), still pooled, or evicted.
    long closed = endpoints.stream().filter(e -> e.socket().isClosed()).count();
    for (val e : popped) assertFalse(e.socket().isClosed());
    assertEquals(200, popped.size() + remaining.size() + closed);
    assertEquals(closed, pool.evictions());
    assertEquals(popped.size(), hitsBeforeDrain);
    assertEquals(0, pool.idleCount());
  }

  private List<Endpoint> drain() {
    val result = new ArrayList<Endpoint>();
    ConnectionPool.PooledConnection c;
    while ((c = pool.pop()) != null) result.add(c.endpoint());
    return result;
  }

  @Test
  void configValidationNamesTheProperty() {
    val negative = new JntlmProperties.Pool();
    negative.setMaxIdle(-1);
    val e1 = assertThrows(IllegalStateException.class, () -> JntlmConfig.validatePool(negative));
    assertTrue(e1.getMessage().contains("jntlm.pool.max-idle"), e1.getMessage());

    val zero = new JntlmProperties.Pool();
    zero.setIdleTimeout(Duration.ZERO);
    val e2 = assertThrows(IllegalStateException.class, () -> JntlmConfig.validatePool(zero));
    assertTrue(e2.getMessage().contains("jntlm.pool.idle-timeout"), e2.getMessage());

    val defaults = new JntlmProperties.Pool();
    JntlmConfig.validatePool(defaults);
    assertEquals(64, defaults.getMaxIdle());
    assertEquals(Duration.ofSeconds(60), defaults.getIdleTimeout());
  }
}
