/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.time.Duration;
import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.ntlm.Credentials;
import org.springframework.context.SmartLifecycle;

/**
 * Pool of cached, already-authenticated connections to the parent proxy.
 *
 * <p>Mirrors CNTLM's {@code connection_list}: because NTLM authentication is bound to a TCP
 * connection, a connection that has completed the handshake can be reused for subsequent requests
 * without re-authenticating. Each cached entry keeps the credentials that were used. The {@link
 * Endpoint} (not the raw socket) is cached so buffered stream state is preserved.
 *
 * <p>Not in CNTLM: the pool is bounded by {@code jntlm.pool.max-idle} (the oldest idle entry is
 * closed beyond it) and entries idle longer than {@code jntlm.pool.idle-timeout} are closed, both
 * lazily on {@link #pop()} and by a background sweeper, so parent-closed sockets do not linger in
 * {@code CLOSE_WAIT}.
 */
@Slf4j
public class ConnectionPool implements SmartLifecycle, AutoCloseable {

  /** A pooled parent-proxy connection together with the credentials it was authenticated with. */
  public record PooledConnection(Endpoint endpoint, Credentials credentials, long idleSinceNanos) {

    // Identity semantics: removal must target this exact entry, never an equal-valued one.
    @Override
    public boolean equals(Object o) {
      return this == o;
    }

    @Override
    public int hashCode() {
      return System.identityHashCode(this);
    }
  }

  private final Deque<PooledConnection> pool = new ConcurrentLinkedDeque<>();
  private final AtomicInteger size = new AtomicInteger();
  private final LongAdder hits = new LongAdder();
  private final LongAdder freshConnections = new LongAdder();
  private final LongAdder evictions = new LongAdder();
  private final int maxIdle;
  private final Duration idleTimeout;
  private final long idleTimeoutNanos;
  private final LongSupplier nanoClock;
  private ScheduledExecutorService sweeper;

  /** Creates a pool with the default bounds ({@link JntlmProperties.Pool}). */
  public ConnectionPool() {
    this(new JntlmProperties.Pool());
  }

  /** Creates a pool bounded by the given (already validated) {@code jntlm.pool.*} settings. */
  public ConnectionPool(JntlmProperties.Pool settings) {
    this(settings.getMaxIdle(), settings.getIdleTimeout(), System::nanoTime);
  }

  /** Creates a pool with explicit bounds and a nanosecond clock (for tests). */
  public ConnectionPool(int maxIdle, Duration idleTimeout, LongSupplier nanoClock) {
    this.maxIdle = maxIdle;
    this.idleTimeout = idleTimeout;
    this.idleTimeoutNanos = idleTimeout.toNanos();
    this.nanoClock = nanoClock;
  }

  /**
   * Removes and returns the most recently pooled connection that has not exceeded the idle timeout,
   * or {@code null} if none. Expired entries met on the way are closed and counted as evictions.
   */
  public PooledConnection pop() {
    PooledConnection connection;
    while ((connection = pool.pollFirst()) != null) {
      size.decrementAndGet();
      if (!isExpired(connection, nanoClock.getAsLong())) {
        hits.increment();
        return connection;
      }
      evict(connection, "expired");
    }
    return null;
  }

  /** Records a newly opened parent connection. */
  void recordFreshConnection() {
    freshConnections.increment();
  }

  long poolHits() {
    return hits.sum();
  }

  long freshConnections() {
    return freshConnections.sum();
  }

  /** Number of pooled connections closed by the size cap or the idle timeout. */
  long evictions() {
    return evictions.sum();
  }

  /** Current number of idle pooled connections. */
  public int idleCount() {
    return size.get();
  }

  /**
   * Adds an authenticated connection to the pool for later reuse. With {@code max-idle: 0} the
   * connection is closed instead; beyond {@code max-idle} the oldest idle entry is closed.
   */
  public void add(Endpoint endpoint, Credentials credentials) {
    if (maxIdle <= 0) {
      endpoint.close();
      return;
    }
    pool.addFirst(new PooledConnection(endpoint, credentials, nanoClock.getAsLong()));
    size.incrementAndGet();
    while (size.get() > maxIdle) {
      val oldest = pool.pollLast();
      if (oldest == null) break;
      size.decrementAndGet();
      evict(oldest, "over max-idle");
    }
  }

  /**
   * Closes and discards every cached connection. Called when the active parent proxy changes
   * (mirrors the cache flush in CNTLM's {@code proxy_connect}).
   */
  public void invalidateAll() {
    PooledConnection c;
    while ((c = pool.pollFirst()) != null) {
      size.decrementAndGet();
      c.endpoint().close();
    }
  }

  /** Closes every pooled connection idle longer than the idle timeout. Run by the sweeper. */
  void sweep() {
    val now = nanoClock.getAsLong();
    for (val connection : pool)
      if (isExpired(connection, now) && pool.removeFirstOccurrence(connection)) {
        size.decrementAndGet();
        evict(connection, "expired");
      }
  }

  private boolean isExpired(PooledConnection connection, long now) {
    return now - connection.idleSinceNanos() >= idleTimeoutNanos;
  }

  private void evict(PooledConnection connection, String reason) {
    evictions.increment();
    log.debug("Closing pooled parent connection ({})", reason);
    connection.endpoint().close();
  }

  /** Starts the background sweeper, running every {@code max(idle-timeout / 2, 1s)}. */
  @Override
  public synchronized void start() {
    if (sweeper != null) return;
    val period = Math.max(idleTimeout.toMillis() / 2, 1000L);
    sweeper =
        Executors.newSingleThreadScheduledExecutor(
            Thread.ofVirtual().name("jntlm-pool-sweeper").factory());
    sweeper.scheduleWithFixedDelay(this::safeSweep, period, period, TimeUnit.MILLISECONDS);
  }

  private void safeSweep() {
    try {
      sweep();
    } catch (RuntimeException e) {
      log.warn("Pool sweep failed", e);
    }
  }

  @Override
  public void stop() {
    close();
  }

  @Override
  public synchronized boolean isRunning() {
    return sweeper != null;
  }

  /** Stops the sweeper and closes every pooled connection. */
  @Override
  public void close() {
    synchronized (this) {
      if (sweeper != null) sweeper.shutdownNow();
      sweeper = null;
    }
    invalidateAll();
  }
}
