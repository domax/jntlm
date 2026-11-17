# Proposal

## Why

The proxy's steady-state path is network-bound, but every request currently pays avoidable parsing,
copying, flushing, socket-probing, and cryptographic setup costs. These costs compound under
keep-alive traffic, large or chunked bodies, concurrent fresh handshakes, and parent failover.

## What Changes

- Optimize HTTP header parsing and serialization without changing wire behavior or malformed-input
  handling.
- Coalesce body and chunk forwarding flushes while preserving request/response boundary latency.
- Replace repeated pooled-socket peer probes with a safer lower-overhead stale-connection strategy.
- Share immutable credential hash material instead of cloning it for every fresh parent connection.
- Reuse per-thread JCA digest, MAC, and DES primitives during NTLM response generation.
- Reduce redundant deep copies of `HttpMessage` and `HttpHeaders`, and optimize hot header lookups
  and enumeration.
- Cache the constant NTLM message prefix and use locale-stable identity normalization.
- Instrument connection-pool hit rate and fresh-handshake concurrency before making pool sizing or
  coordination changes.
- Add repeatable concurrent performance benchmarks covering keep-alive requests, body forwarding,
  fresh NTLM handshakes, pooling, failover, and flag detection.
- Preserve CNTLM wire semantics, authentication correctness, connection reuse, and existing
  configuration behavior.

## Capabilities

### New Capabilities

- `proxy-performance`: Efficient HTTP forwarding, NTLM handshake processing, connection reuse, and
  measurable throughput under concurrent load.

### Modified Capabilities

- `ntlm-flags-detection`: Preserve bounded probing, caching, failover invalidation, and
  single-flight behavior while reducing probe and message-construction overhead.

## Impact

- **HTTP layer:** `HttpIo`, `HttpMessage`, and `HttpHeaders`.
- **Proxy layer:** `Endpoint`, `RequestForwarder`, `ProxyAuthenticator`, `NtlmFlagsResolver`,
  `ConnectionPool`, and `ParentProxyManager`.
- **NTLM layer:** `Credentials`, `NtlmMessages`, `NtlmCrypto`, `NtlmHashes`, and `Md4`.
- **Tests/tooling:** new benchmark fixtures and performance regression tests; existing integration and
  protocol tests remain mandatory.
- **Operational behavior:** add low-overhead metrics or counters for pool hits, fresh handshakes,
  detection probes, and failovers. No externally visible protocol or configuration changes are
  intended.

### Assumptions and Out of Scope

- Benchmark thresholds will be established from a representative baseline rather than inventing
  hardware-specific absolute numbers.
- No asynchronous HTTP rewrite, servlet stack, protocol upgrade, or new runtime dependency is
  required.
- No change to NTLM dialect selection, security policy, header semantics, or parent-proxy
  selection policy is included.
- Pool sizing and handshake coordination remain measurement-driven; instrumentation alone does not
  change their policy.
