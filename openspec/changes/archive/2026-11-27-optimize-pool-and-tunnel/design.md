<!--suppress MarkdownUnresolvedLinkLabel -->
## Context

Measured and read during exploration:

- **`ConnectionPool`.** A `ConcurrentLinkedDeque<PooledConnection>` with LIFO `pop`/`add` and
  `LongAdder` hit/fresh counters.
  - No cap and no timestamps.
  - Pooled sockets are only checked when reused: an EOF on the parent response triggers one retry
    if the request had no body (`RequestForwarder` loop 1). Otherwise the client is closed without
    a response.
- **`Endpoint`.** Wraps the socket in `BufferedInputStream`/`BufferedOutputStream` (8 KiB each).
  `isPeerClosed()` costs about 1.2–1.3 ms when the peer is alive (1 ms `SO_TIMEOUT` peek). It is
  used on the client socket at the end of each keep-alive iteration and in `ProxyAuthenticator`,
  never on a pooled parent socket. The archived spec's "no probe on healthy pooled connection"
  rule therefore holds.
- **`HttpIo.readLine`.** Calls `in.read()` once per byte into a `ByteArrayOutputStream`. On JDK 21,
  `BufferedInputStream.read()` takes an internal lock, and `ByteArrayOutputStream.write` is
  `synchronized`, so each header byte costs two lock acquisitions.
- **`HttpIo.tunnel`/`pump`.** 8 KiB buffer.
  - Reads go through `BufferedInputStream`.
  - Writes go to `BufferedOutputStream` followed by `flush()` on every read: an arraycopy into the
    buffer, then a socket write.
- **Header and body sends.** `HttpIo` writes headers and flushes, then writes the body, so small
  messages take two `write(2)` calls and possibly two TCP segments (Nagle/delayed-ACK interplay on
  some stacks).

Constraints:

- Keep CNTLM parity of the forwarding control flow (labeled two-pass loop).
- Keep the strict framing and limits added by `harden-http-framing-and-limits`. This change lands
  after it and reuses its `HttpLimits`, `HttpProtocolException` and the tunnel idle timeout.

## Goals / Non-Goals

**Goals:**
- Bound idle parent sockets in number and age; no FD/`CLOSE_WAIT` growth after bursts.
- Never silently drop a request because a pooled connection went stale.
- Raise tunnel throughput and cut per-request CPU for header parsing and small exchanges.
- Make these gains measurable in `ProxyPerformanceBenchmarkTest`.

**Non-Goals:**
- Pre-warmed connections, removing `isPeerClosed`, NTLM crypto caching, JVM startup tuning,
  HTTP/2, half-close (see proposal).

## Decisions

### D1. Pool entries carry an idle timestamp; eviction is lazy plus a sweeper
- `PooledConnection(endpoint, credentials, long idleSinceNanos)`.
- **`add`:**
  - If `maxIdle == 0`, close the endpoint.
  - Otherwise `addFirst`. If size > `maxIdle`, `pollLast` and close it (oldest), counting an
    eviction.
  - Size is tracked with an `AtomicInteger`, because `ConcurrentLinkedDeque.size()` is O(n).
- **`pop`:** loop `pollFirst`. Entries older than `idleTimeout` are closed and counted as evictions;
  the first fresh one is returned and counted as a hit. Because the deque is LIFO, expired entries
  are at the tail, so the loop usually ends on the first poll.
- **Sweeper:** a single scheduled virtual-thread task (`Executors.newSingleThreadScheduledExecutor`
  with a virtual thread factory) runs every `max(idleTimeout / 2, 1s)`. It polls from the tail
  while the entry is expired and closes it.
  - It is started and stopped by a `SmartLifecycle` on the pool, or by `@PreDestroy`, so tests that
    construct `ConnectionPool` manually can call `close()`.
  - `invalidateAll` is unchanged.
- **Concurrency:** a sweeper `pollLast` racing a `pop` `pollFirst` on the same last element is safe:
  the deque guarantees exactly one of them gets the element.

Alternatives:
- An `isPeerClosed` probe on `pop`. Rejected: it adds about 1.3 ms to every pooled request, which
  is exactly what the archived spec forbids.
- A `ScheduledExecutor` per connection. Rejected: too much overhead.
- Third-party pool (commons-pool). Rejected: new dependency for about 60 lines.

Defaults: `max-idle: 64` covers a busy desktop (browsers keep about 6 connections per host, and
everything goes through one parent). `idle-timeout: 60s` is below common proxy keep-alive limits
(Squid 120 s, BlueCoat about 60–120 s), and the sweeper closes before the parent does in most
setups.

### D2. Stale connection with a non-replayable body gets 502
In `RequestForwarder` loop 1, when `data1 == null` (or `recvHeaders` throws) and `wasCached`:

- If the request had no body: unchanged (retry on a fresh connection).
- Otherwise: if no response bytes were sent to the client, send `ErrorPages` 502 with
  `Connection: close`, then discard the parent connection and close.

The request is never replayed, because the body has already been streamed and cannot be re-read
(no buffering of request bodies, which keeps memory bounded). Javadoc: "Not in CNTLM: CNTLM closes
silently." This uses the same "nothing sent yet" guard as change 1's 502/504 handling.

Alternative: buffer bodies of 64 KiB or less for replay. Rejected for now: non-idempotent POST
replay is risky, and D1 makes stale reuse rare.

### D3. `HttpInputStream`: unsynchronized buffered input with line scanning
New `http/HttpInputStream extends InputStream` (final, not thread-safe by contract: each endpoint's
input is read by one thread at a time, which `RequestForwarder` and the tunnel guarantee).

- 16 KiB `byte[]` with `pos`/`limit`.
- `read()`, `read(b, off, len)`: a large `len` with an empty buffer bypasses into the socket stream.
- `available()`.
- `readLine(int max)`: scan `buf[pos..limit)` for `\n`. If found, build the `String` (ISO-8859-1)
  directly from the buffer slice. Otherwise append the slice to a reusable growable array and
  refill. Throw the same "line too long" `HttpProtocolException` as today once `max` is exceeded.
- `drainBuffered(OutputStream)` writes any buffered bytes. Used when a tunnel starts.
- `peekClosed(Socket)` provides `Endpoint.isPeerClosed` semantics: with an empty buffer, a 1 ms
  timed single-byte fill instead of `mark`/`reset`.

`Endpoint.in()` returns `HttpInputStream`. `HttpIo.readLine(InputStream, max)` uses the fast path
when given an `HttpInputStream`; otherwise it keeps the byte loop, so the existing tests that pass
`ByteArrayInputStream` still work.

Alternative: keep `BufferedInputStream` and use `readNBytes`. Rejected: it can't scan for a
delimiter without over-reading.

### D4. Tunnel relay writes straight to socket streams
On entering `HttpIo.tunnel`:

1. Flush both `BufferedOutputStream`s.
2. Write any client/server `HttpInputStream` buffered bytes to the opposite raw socket
   `OutputStream`.
3. Pump with a 16 KiB buffer: `in.read(buf)` on `HttpInputStream` (which bypasses its buffer for
   large reads), then `rawOut.write(buf, 0, n)` with no `flush` call. The raw socket stream is
   unbuffered.

- Close-both and logging semantics are unchanged.
- The change 1 tunnel idle timeout is applied as before.
- `Endpoint` exposes `rawOut()`, the socket's `OutputStream`, for this.

### D5. Coalesced small writes
`HttpIo.sendHeaders` gets a `flush` flag. When the message has `Content-Length` of 8192 or less
and is not chunked, the forwarder:

1. Writes headers without flushing.
2. Calls `dataTransfer`, which reads the full body (at most 8 KiB) into the 8 KiB output buffer.
3. Flushes once.

Larger bodies and chunked bodies: unchanged (flush after headers so streaming starts
immediately, per the "Large body still streams" scenario). This applies symmetrically to requests
(client→parent) and responses (parent→client) in the two-pass loop, and to the 407 handshake
messages in `ProxyAuthenticator`.

Alternative: `TCP_NODELAY` off. Rejected: it doesn't remove the extra syscall, and it adds latency.

### D6. Instrumentation and benchmark
- `ConnectionPool` gets an `evictions()` `LongAdder` and `idleCount()`, logged with the existing
  counters at DEBUG.
- `ProxyPerformanceBenchmarkTest` gets these workloads:
  - (a) N keep-alive requests on one client connection.
  - (b) An 8 MiB `CONNECT` echo, reporting MB/s.
  - (c) Burst of 32 concurrent clients, then idle past `idle-timeout`, asserting the pool drains to
    0 open parent sockets.
  - (d) Header-parse micro-workload: 10k requests × 30 headers.
- Each run records results before and after, on the same JDK and machine, in the task notes; no
  CI thresholds.

## Risks / Trade-offs

- [The sweeper closes a connection just as the parent would have kept it] → Only costs one extra
  NTLM handshake. `idle-timeout` is configurable.
- [A custom `HttpInputStream` has subtle bugs (off-by-one at buffer boundaries, lost bytes at
  tunnel start)] → Unit tests with 1-byte and 16 KiB-boundary chunked sources, a tunnel
  "bytes buffered before the tunnel" test, and the full integration suite.
- [Thread-safety assumptions on `HttpInputStream`] → Document that it is single-reader. The tunnel
  uses each input from exactly one pump thread, and `isPeerClosed` is only called from the owning
  handler thread.
- [Coalescing delays headers for slow small bodies (up to 8 KiB)] → Bounded by `parent-read-timeout`
  or `client-idle-timeout`. Small bodies normally arrive in the same segment as the headers.
- [The 502 replaces a silent close for some clients that previously retried on their own] →
  Clients that retry on 502 or on close behave the same, and the user gets a visible error instead
  of a hang or reset.

## Migration Plan

- New optional `jntlm.pool.*` keys with defaults; no config changes are required.
- Rollback: redeploy the previous jar. Unknown `jntlm.pool` keys are ignored by older versions.
- Version: bump the minor version again only if this ships separately from
  `harden-http-framing-and-limits`. If both ship together, the change 1 bump (`1.4.0`) covers both.

## Open Questions

- Should `max-idle` also be applied per parent proxy if multiple parents are active at once? Today
  `invalidateAll` on failover means only one parent's connections are pooled, so a single global
  cap is enough.
