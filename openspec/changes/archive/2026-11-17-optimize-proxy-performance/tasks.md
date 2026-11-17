# Tasks

## 1. Establish performance baselines and fixtures

- [x] 1.1 Add an in-process benchmark fixture based on `MockParentProxy` that can generate
  keep-alive, fixed-length (1 KiB and 1 MiB), chunked, fresh-handshake, pooled, and
  flag-detection workloads; verify it can run repeatedly with deterministic status, body,
  handshake, and probe assertions.
- [x] 1.2 Add baseline measurements for throughput, latency, allocation/resource observations, pool
  hits, fresh handshakes, detection probes, and concurrent fresh handshakes; verify the
  benchmark report is reproducible under the documented Gradle/JVM command.

## 2. Optimize HTTP parsing and forwarding

- [ ] 2.1 Replace byte-at-a-time header-line parsing with bounded block scanning over the existing
  buffered input stream; preserve CRLF, EOF, malformed start-line, and header parsing behavior;
  verify `HttpMessageTest`, `HttpHeadersTest`, and oversized/malformed input tests pass.
- [x] 2.2 Optimize header serialization and enumeration with direct iteration and reusable encoding
  paths while preserving header order, duplicate values, case-insensitive names, and ISO-8859-1
  wire bytes; verify serialized golden cases and the full HTTP unit-test set.
- [x] 2.3 Coalesce fixed-length and chunked body writes and flushes while flushing complete headers
  promptly; verify large and chunked integration cases preserve exact body bytes, framing, trailers,
  and response latency behavior.
- [ ] 2.4 Add targeted `HttpMessage`/`HttpHeaders` copy and mutation helpers and update
  authentication, detection, retry, and forwarding paths to avoid redundant deep copies; verify
  request isolation across retries and concurrent clients.

## 3. Optimize pooled connection handling

- [x] 3.1 Remove the unconditional `Endpoint.isPeerClosed()` timeout/peek from the healthy pooled
  connection path and make stale detection read/write-driven; verify healthy reuse performs no
  peer-status probe.
- [x] 3.2 Preserve stale pooled-connection retry, request replay, peer-close, and parent failover
  behavior with focused integration tests; verify no request is lost or duplicated when the peer
  closes before reuse.
- [x] 3.3 Add low-overhead counters for pool hits, fresh parent connections, concurrent fresh
  handshakes, and parent failovers; verify counters change at the expected points without changing
  forwarded responses.

## 4. Reduce credential and NTLM allocation overhead

- [x] 4.1 Make configured credential hash arrays immutable/shared across per-connection credential
  views while keeping mutable flags and connection state isolated; verify repeated and concurrent
  handshakes cannot mutate shared credentials and all existing credential tests pass.
- [x] 4.2 Cache the constant NTLMSSP message prefix and change identity normalization to
  `Locale.ROOT`; verify NTLM Type-1/Type-3 vector outputs and non-ASCII identity behavior remain
  correct.
- [x] 4.3 Add thread-confined reusable `MessageDigest`, `Mac`, and DES `Cipher` state with explicit
  reset/reinitialization before use; verify concurrent NTLM handshakes never cross-contaminate
  cryptographic state and all NTLM vector tests pass.
- [x] 4.4 Re-run the NTLM handshake benchmark and compare allocation/resource observations with the
  baseline; verify generated messages differ only where protocol nonces and timestamps require it.

## 5. Optimize flag detection and authentication hot paths

- [ ] 5.1 Reduce redundant message construction in `ProxyAuthenticator` and
  `NtlmFlagsResolver` using the targeted copy/header helpers without changing probe templates,
  authentication headers, or body suppression; verify all flag resolver and forwarding integration
  tests pass.
- [x] 5.2 Add low-overhead detection-probe counters and preserve single-flight caching, parent
  invalidation, bounded candidate probing, and rejection logging; verify cached requests add no
  probes or rejection logs.
- [x] 5.3 Benchmark fresh NTLM handshakes and lazy/eager flag detection under concurrent load;
  verify probe counts, accepted flags, request bodies, and parent handshakes match the protocol
  scenarios.

## 6. Validate and document performance behavior

- [ ] 6.1 Run the complete workload matrix for keep-alive GETs, 1 KiB and 1 MiB bodies, chunked
  responses, fresh handshakes, pooling, failover, and flag detection; verify throughput and
  latency improve or remain within an agreed regression threshold against the baseline.
- [x] 6.2 Run `./gradlew spotlessApply build` and the complete test suite; verify formatting,
  license headers, protocol tests, NTLM vectors, and integration tests all pass.
- [x] 6.3 Document benchmark commands, workload sizes, measured counters, and interpretation of
  results in the existing project documentation; verify every documented command runs from a clean
  checkout without requiring a production metrics service.

## Workflow follow-up

- Review benchmark results and protocol diffs before implementation approval.
- Archive the change with `/opsx-archive` after implementation and review are complete.
