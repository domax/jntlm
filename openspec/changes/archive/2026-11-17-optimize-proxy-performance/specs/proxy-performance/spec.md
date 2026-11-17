# Spec Delta

## Purpose

Improves the proxy's throughput and resource efficiency while preserving HTTP wire compatibility,
NTLM authentication behavior, connection reuse, and failover semantics.

## ADDED Requirements

### Requirement: Efficient HTTP forwarding
The system SHALL forward headers and bodies with bounded memory, no unnecessary per-byte parsing,
and no redundant flushes that materially increase system calls.

#### Scenario: Large response body
- **GIVEN** a parent returns a large fixed-length response
- **WHEN** the proxy forwards it to the client
- **THEN** the complete body is relayed with bounded buffering and without flushing once per small read

#### Scenario: Chunked response
- **GIVEN** a parent returns a chunked response with trailers
- **WHEN** the proxy forwards it
- **THEN** chunk framing, trailers, and body bytes remain unchanged

### Requirement: Protocol-preserving connection reuse
The system SHALL detect stale pooled parent connections without adding a blocking probe to every
successful keep-alive request, while preserving retry and failover behavior.

#### Scenario: Healthy pooled connection
- **GIVEN** an authenticated parent connection is reusable
- **WHEN** a client sends another request
- **THEN** the request uses the pooled connection without an extra peer-status socket probe

#### Scenario: Stale pooled connection
- **GIVEN** a pooled parent connection has been closed by the peer
- **WHEN** the proxy attempts the next request
- **THEN** the proxy discards or retries the connection and does not lose or duplicate the request

### Requirement: Efficient NTLM processing
The system SHALL reuse immutable credential material and thread-confined cryptographic state where
safe, without changing generated NTLM message bytes except for required nonces and timestamps.

#### Scenario: Repeated fresh handshakes
- **GIVEN** multiple fresh parent connections authenticate with the same configured credentials
- **WHEN** Type-1 and Type-3 messages are generated
- **THEN** password-hash material is not deep-copied for each connection and authentication remains valid

#### Scenario: Concurrent handshakes
- **GIVEN** multiple virtual threads authenticate concurrently
- **WHEN** cryptographic responses are generated
- **THEN** cryptographic state is isolated per thread and no response uses another request's state

### Requirement: Observable performance instrumentation
The system SHALL expose low-overhead counters or equivalent diagnostics for parent-pool hits,
fresh handshakes, flag-detection probes, and parent failovers.

#### Scenario: Pool reuse measurement
- **WHEN** an authenticated pooled connection serves a request
- **THEN** the pool-hit measurement increases without changing the forwarded response

#### Scenario: Failover measurement
- **WHEN** the active parent changes after connection failure
- **THEN** the failover measurement increases and existing pool invalidation behavior is preserved

### Requirement: Performance regression coverage
The project SHALL provide repeatable performance coverage for keep-alive traffic, body forwarding,
fresh NTLM handshakes, pooling, failover, and flag detection.

#### Scenario: Benchmark execution
- **WHEN** the performance benchmark suite runs against an in-process parent fixture
- **THEN** it reports throughput, latency, and allocation or resource observations for each workload

#### Scenario: Correctness under benchmark load
- **WHEN** benchmark workloads run concurrently
- **THEN** all requests complete with correct bodies and status codes and existing protocol tests remain passing
