/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.LongAdder;
import net.domax.jntlm.ntlm.Credentials;
import org.springframework.stereotype.Component;

/**
 * Pool of cached, already-authenticated connections to the parent proxy.
 *
 * <p>Mirrors CNTLM's {@code connection_list}: because NTLM authentication is bound to a TCP
 * connection, a connection that has completed the handshake can be reused for subsequent requests
 * without re-authenticating. Each cached entry keeps the credentials that were used. The {@link
 * Endpoint} (not the raw socket) is cached so buffered stream state is preserved.
 */
@Component
public class ConnectionPool {

  /** A pooled parent-proxy connection together with the credentials it was authenticated with. */
  public record PooledConnection(Endpoint endpoint, Credentials credentials) {}

  private final Deque<PooledConnection> pool = new ConcurrentLinkedDeque<>();
  private final LongAdder hits = new LongAdder();
  private final LongAdder freshConnections = new LongAdder();

  /** Removes and returns a cached connection, or {@code null} if the pool is empty. */
  public PooledConnection pop() {
    var connection = pool.pollFirst();
    if (connection != null) hits.increment();
    return connection;
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

  /** Adds an authenticated connection to the pool for later reuse. */
  public void add(Endpoint endpoint, Credentials credentials) {
    pool.addFirst(new PooledConnection(endpoint, credentials));
  }

  /**
   * Closes and discards every cached connection. Called when the active parent proxy changes
   * (mirrors the cache flush in CNTLM's {@code proxy_connect}).
   */
  public void invalidateAll() {
    PooledConnection c;
    while ((c = pool.pollFirst()) != null) c.endpoint().close();
  }
}
