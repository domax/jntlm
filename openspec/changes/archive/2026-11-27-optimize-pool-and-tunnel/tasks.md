# Tasks

## 1. Bounded idle pool

- [x] 1.1 In `config/JntlmProperties`, add `private Pool pool = new Pool();` with nested `@Data public static class Pool { int maxIdle = 64; Duration idleTimeout = Duration.ofSeconds(60); }` and Javadoc; validate in `JntlmConfig` (negative `max-idle` or non-positive `idle-timeout` → `IllegalStateException` naming the property). Add a commented `pool:` block to `application.yml`. Verify `./gradlew compileJava`.
- [x] 1.2 In `proxy/ConnectionPool`, add `idleSinceNanos` to `PooledConnection`, an `AtomicInteger` size, `maxIdle`/`idleTimeout` (constructor from `JntlmProperties.Pool`, keeping a test-friendly constructor), cap-on-add closing the tail, expire-on-pop, and an `evictions` `LongAdder` plus `idleCount()` (design D1). Inject a `LongSupplier` nano clock for tests. Verify with 1.4.
- [x] 1.3 Add the background sweeper on a single virtual-thread scheduled executor running every `max(idleTimeout/2, 1s)`, started/stopped with the Spring lifecycle and closable from tests via `close()`. Verify with 1.4.
- [x] 1.4 Add `src/test/java/net/domax/jntlm/proxy/ConnectionPoolTest` covering: LIFO reuse; cap closes oldest; `max-idle: 0` closes immediately; expired entry skipped and closed on `pop`; sweeper closes expired entries with no traffic (real 1 s timeout, `Awaitility`-free polling with deadline); eviction/hit counters; concurrent `add`/`pop`/sweep stress with no double-close or lost entry; config validation messages. Verify `./gradlew test --tests '*ConnectionPoolTest'` passes.

## 2. No silent drop on stale reuse

- [x] 2.1 In `proxy/RequestForwarder` loop 1, when a cached connection returns no response and the request had a body, send `ErrorPages` 502 with `Connection: close` if nothing was sent to the client yet, discard the parent, and close; keep the body-less retry unchanged; Javadoc "Not in CNTLM" (design D2). Verify with 2.2.
- [x] 2.2 Extend `ProxyForwardingIntegrationTest` (or `HttpFramingIntegrationTest` from change 1): `MockParentProxy` closes a pooled connection after the first exchange; a `POST` with a body over the same client connection receives `502` and is received by the parent at most once; a subsequent `GET` scenario still retries transparently and gets `200`; and an expired pooled connection (idle-timeout 1 s, wait 2 s) is not reused (`parent.connectionsAccepted()` increases, request succeeds). Verify `./gradlew test --tests '*IntegrationTest'` passes.

## 3. Fast header line reading

- [x] 3.1 Add `http/HttpInputStream` (unsynchronized, single-reader, 16 KiB buffer) with `read()`, `read(byte[],int,int)` bypassing the buffer for large reads when empty, `available()`, `readLine(int max)` scanning for LF, `drainBuffered(OutputStream)`, and a timed peek used by `isPeerClosed` (design D3). Verify with 3.3.
- [x] 3.2 Make `proxy/Endpoint` use `HttpInputStream` for `in()`, implement `isPeerClosed` with its peek, and expose `rawOut()`; make `HttpIo.readLine` use `HttpInputStream.readLine` when available, otherwise the existing byte loop. Keep the header limits and `HttpProtocolException` behavior from change 1. Verify with 3.3.
- [x] 3.3 Add `src/test/java/net/domax/jntlm/http/HttpInputStreamTest`: lines split across 1-byte reads and across a 16 KiB refill boundary; CRLF preserved; EOF mid-line returns partial line then null as today; max length exceeded throws; bulk `read` after partial line returns remaining buffered bytes first; `drainBuffered` returns exactly the unread bytes. Verify `./gradlew test --tests '*HttpInputStreamTest' --tests '*HttpIoFramingTest'` passes.

## 4. Tunnel relay

- [x] 4.1 Rewrite `HttpIo.tunnel`/`pump` per design D4: flush both buffered outputs, drain both `HttpInputStream` buffers to the opposite raw outputs, then pump with a 16 KiB buffer into the raw socket output without per-read `flush`; keep close-both, logging and change 1's tunnel idle timeout. Verify with 4.2.
- [x] 4.2 Add tunnel tests (extend `MockParentProxy` with a CONNECT echo mode if missing): 8 MiB random echo is byte-identical; parent `200` and first tunneled bytes sent in one write arrive first at the client; either side closing closes both. Verify `./gradlew test --tests '*ProxyForwardingIntegrationTest'` passes.

## 5. Coalesced small writes

- [x] 5.1 Add a no-flush variant of header sending in `HttpIo` and use it in `RequestForwarder` (both directions) and `ProxyAuthenticator` when the body is fixed-length of 8192 bytes or less, flushing once after the body; leave larger and chunked bodies unchanged (design D5). Verify with 5.2.
- [x] 5.2 Add tests with a flush-counting output stream wrapper: 512-byte response → one flush with byte-identical output; 10 MiB response → headers flushed before the body is complete; chunked → unchanged bytes. Verify `./gradlew test --tests '*HttpIo*'` passes.

## 6. Benchmarks and documentation

- [x] 6.1 Extend `ProxyPerformanceBenchmarkTest` with workloads per design D6 (keep-alive on one client connection, 8 MiB CONNECT echo MB/s, burst-then-idle pool drain to 0 open parent sockets, 10k × 30-header parse) and correctness assertions. Record before/after numbers on the same machine in the PR description. Verify `./gradlew test --tests '*ProxyPerformanceBenchmarkTest'` passes and reports each workload.
- [x] 6.2 Update `README.md` (configuration table rows for `jntlm.pool.max-idle` and `jntlm.pool.idle-timeout`, and the 502-on-stale-body behavior) and `AGENTS.md` (`ConnectionPool` is bounded with idle eviction; `Endpoint` uses `HttpInputStream`). Verify defaults match `application.yml`.

## 7. Integration checks

- [x] 7.1 Run `./gradlew spotlessApply build` and verify it succeeds with all tests green.
- [x] 7.2 Run the benchmark and verify tunnel throughput and header-parse workloads improve versus the baseline with no regression >10% in the existing workloads.
- [x] 7.3 Manual smoke (local profile): browse several HTTPS sites through the proxy, wait > `idle-timeout`, verify via `lsof -p <pid> | grep -c CLOSE_WAIT` that no `CLOSE_WAIT` parent sockets remain, then browse again successfully.

## Workflow follow-up

- Apply only after `harden-http-framing-and-limits` is implemented.
- Archive with `/opsx-archive`, syncing the `proxy-performance` delta.
