# Design

## Context

The proxy uses hand-rolled HTTP I/O over buffered sockets, deep-copying mutable messages and
headers between forwarding and authentication steps. `Endpoint.isPeerClosed()` performs a timeout
change and one-byte peek, `HttpIo` parses lines one byte at a time, and body forwarding flushes
frequently. NTLM response generation creates JCA primitives and credential copies on fresh
connections. Existing integration tests exercise protocol correctness but do not provide a
repeatable throughput or allocation baseline.

## Goals / Non-Goals

**Goals:**

- Reduce CPU, allocation, syscall, and cryptographic setup overhead on request and handshake hot
  paths.
- Preserve exact HTTP and NTLM wire semantics, including malformed-input handling, body framing,
  keep-alive, retries, failover, and flag-detection behavior.
- Add low-overhead measurements and reproducible workloads so optimization decisions are evidence
  based.
- Keep the implementation compatible with Java 21 virtual threads and existing project
  conventions.

**Non-Goals:**

- Replacing raw sockets with a servlet or asynchronous HTTP framework.
- Changing authentication dialects, security defaults, parent selection, or connection-pool policy
  before measurements justify it.
- Adding a production metrics backend or external benchmark dependency.
- Optimizing cryptographic algorithms by weakening them or changing protocol output.

## Decisions

### D1. Preserve the existing wire-level abstractions

Improve `HttpIo`, `HttpMessage`, and `HttpHeaders` in place rather than introducing a second HTTP
representation. This keeps the CNTLM-style forwarding control flow intact and makes existing
protocol tests authoritative. A full HTTP library is rejected because it adds parsing behavior and
allocation overhead that could diverge from the current proxy semantics.

### D2. Use reusable bounded buffers for line and body operations

Replace one-byte line reads with block scanning over existing buffered streams and retain explicit
maximum line/header limits. Coalesce writes and flush once per complete forwarding unit, while
preserving a flush at request/response boundaries where clients or parents need prompt headers.
Unbounded buffering and silent truncation are rejected; malformed or oversized input must remain an
explicit protocol failure.

### D3. Make stale-connection handling read-driven

Remove the unconditional socket timeout/peek from the healthy pooled path. Let the next header read
or write identify stale connections, then reuse the existing retry-on-407/connection-failure path.
If a look-ahead is necessary for a specific edge case, isolate it to that failure path rather than
the successful path. This avoids changing buffered stream state or losing pending bytes.

### D4. Share immutable credentials and confine cryptographic state

Treat configured password hashes as immutable and share them across credential views; only
connection-specific flags and identity metadata remain mutable. Cache `MessageDigest`, `Mac`, and
`Cipher` instances per thread, resetting or reinitializing them before use. Global shared mutable
JCA instances are rejected because concurrent virtual threads would corrupt authentication state.

### D5. Add targeted message/header operations

Introduce focused copy or mutation helpers where they eliminate full deep copies, while retaining
full `copy()` for callers that require isolation. Replace stream/lambda operations in hot lookups
and serialization with direct iteration and preserve case-insensitive names, duplicate values, and
header order.

### D6. Keep NTLM output deterministic except for protocol nonces

Cache the constant NTLMSSP prefix and use `Locale.ROOT` for case normalization. Do not cache
generated Type-3 responses, timestamps, challenges, or nonces. Existing vector tests and
integration handshakes remain the compatibility oracle.

### D7. Instrument before changing pool policy

Add counters for pool hits, fresh handshakes, detection probes, failovers, and concurrent fresh
handshakes. Keep the first implementation package-visible/test-readable and log-free on the
normal path; no metrics endpoint is added. Use the existing test fixture and a small in-process
benchmark harness rather than adding a runtime metrics system. Pool limits, request coalescing, or
new fairness rules are not implemented unless benchmark evidence and a subsequent approved scope
require them.

### D8. Benchmark with correctness assertions

Create repeatable workloads for keep-alive GETs, 1 KiB and 1 MiB fixed-length bodies, chunked
bodies, fresh NTLM authentication, pooled reuse, parent failover, and flag detection. Record
throughput, latency, and allocation/resource observations where the JVM permits. Each workload
also asserts status, body, handshake, and probe counts so performance tests cannot hide protocol
regressions.

## Risks / Trade-offs

- [Read-driven stale detection may discover a dead pooled socket later] -> Preserve the existing
  retry and request replay path, and add tests for peer-close before the next request.
- [Fewer flushes may increase response latency for streaming data] -> Flush complete headers
  immediately and benchmark both small interactive responses and large/chunked bodies.
- [Shared credential arrays could be mutated accidentally] -> Make ownership explicit, prevent
  callers from receiving mutable shared state, and test concurrent handshakes.
- [Thread-local JCA state can retain memory per platform thread] -> Scope caches to virtual-thread
  operations or a bounded reusable context and measure allocation; avoid unbounded global caches.
- [Microbenchmarks can be noisy] -> Prefer repeated in-process scenarios, report distributions, and
  compare optimized and baseline commits under the same JVM settings.
- [Instrumentation can affect hot paths] -> Use primitive counters and disabled-by-default
  diagnostics where possible, and verify overhead with instrumentation enabled and disabled.

## Migration Plan

1. Establish benchmark and protocol baselines before changing hot paths.
2. Apply parsing/flush and connection-path optimizations with focused tests after each group.
3. Apply credential and cryptographic reuse, then run all NTLM vectors and integration tests.
4. Add or verify instrumentation and compare benchmark results against the baseline.
5. Deploy with the existing configuration; rollback is a binary rollback because no configuration
   or wire-format migration is required.
