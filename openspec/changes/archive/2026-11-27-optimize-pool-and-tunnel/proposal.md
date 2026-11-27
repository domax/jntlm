# Proposal

## Why

The parent-connection pool is an unbounded LIFO deque with no idle expiry. Each burst of
concurrent requests leaves behind as many authenticated sockets as the burst's peak, and they are
held forever. Corporate proxies typically drop idle connections after 30–120 s, so those sockets
pile up in `CLOSE_WAIT` (FD leak) and are found stale only when reused. Reuse of a stale socket is
retried for body-less requests. A request with a body is silently dropped (the client sees the
connection close with no response).

Several hot paths also do avoidable work:

- `CONNECT` tunnels (most traffic is HTTPS) copy through an extra buffer layer and flush on every
  8 KiB read.
- Header lines are parsed one byte at a time through two synchronized streams.
- Small requests/responses are sent as two writes (headers, then body).

## What Changes

- Bound the parent connection pool:
  - New `jntlm.pool.max-idle` (default 64; `0` disables pooling) and `jntlm.pool.idle-timeout`
    (default 60s).
  - Expired idle connections are closed by a background sweeper and skipped when popped.
  - When the pool is full, the oldest idle connection is closed.
  - Evictions are counted alongside the existing pool-hit/fresh-connection counters.
- A stale pooled connection that fails on a request whose body was already forwarded, and so
  cannot be replayed, yields `502 Bad Gateway` to the client instead of a silent close. Body-less
  requests keep today's transparent single retry.
- Faster `CONNECT` tunnel relay:
  - 16 KiB per-direction buffers.
  - Reads drain any already-buffered bytes, then go straight to the socket streams with no
    per-read copy through `BufferedOutputStream`.
  - Close-both semantics and the `tunnel-idle-timeout` from `harden-http-framing-and-limits` stay.
- Buffer-scanning header line reader: an unsynchronized input stream in `Endpoint` that finds LF
  inside its buffer, replacing the per-byte `read()` loop. Wire behavior, line limits and
  validation are unchanged.
- Coalesced small writes: headers and a fixed-length body of at most 8 KiB are sent in one
  flush/system call, for both requests and responses.
- Benchmark workloads for multiple keep-alive requests on one client connection, CONNECT tunnel
  throughput, stale-pool eviction, and header parsing.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `proxy-performance`:
  - Adds requirements for a bounded idle pool, efficient tunnel relay and coalesced small writes.
  - Tightens stale-connection handling (502 instead of a silent close when replay is impossible).
  - Extends the benchmark coverage.

## Impact

- Code: `proxy/ConnectionPool`, `proxy/Endpoint` (new buffered input stream), `http/HttpIo`
  (`readLine`, `tunnel`/`pump`, header/body flush), `proxy/RequestForwarder` (stale-retry 502),
  `config/JntlmProperties` (`Pool` block), `config/JntlmConfig`.
- Configuration: new optional `jntlm.pool.*` keys; `application.yml`, `README.md`, `AGENTS.md`.
- Tests: `ConnectionPool` unit tests, stale-connection integration tests, extended
  `ProxyPerformanceBenchmarkTest`.
- No new runtime dependencies.
- Depends on `harden-http-framing-and-limits` (same `HttpIo` methods); implement after it.

## Assumptions

- A 60 s idle timeout is below typical corporate-proxy idle cut-offs, so most stale reuse is
  avoided. Users can tune it. Defaults keep CNTLM-like pooling for normal usage.
- Closing the oldest idle connection when full is acceptable. The LIFO pop already prefers the
  most recently used connection.

## Out of Scope

- Pre-warming authenticated parent connections in the background (needs synthetic traffic to the
  parent; revisit with metrics).
- Removing the remaining `isPeerClosed` probes:
  - The client-side probe is not on the request latency path.
  - The authenticator probe costs about 1.3 ms per fresh handshake only.
- Changes to NTLM crypto caching (virtual threads are per-connection; there is nothing to reuse).
- JVM startup tuning (CDS/AOT), HTTP/2, half-close tunnels.
