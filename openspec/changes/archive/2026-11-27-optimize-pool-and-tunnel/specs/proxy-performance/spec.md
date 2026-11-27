# Spec Delta

## ADDED Requirements

### Requirement: Bounded idle connection pool
The system SHALL keep at most `jntlm.pool.max-idle` idle authenticated parent connections (default
64; `0` disables pooling) and SHALL close an idle connection once it has been idle longer than
`jntlm.pool.idle-timeout` (default `60s`), both when it would be reused and in the background
without waiting for a request. Adding to a full pool SHALL close the oldest idle connection.

#### Scenario: Idle connection expires without traffic
- **GIVEN** `jntlm.pool.idle-timeout: 1s` and one pooled parent connection
- **WHEN** no request arrives for 3 seconds
- **THEN** the pooled connection is closed and the pool is empty
- **AND** the eviction counter has increased

#### Scenario: Expired connection is not reused
- **GIVEN** a pooled connection idle longer than `jntlm.pool.idle-timeout`
- **WHEN** a client sends a request before the background sweep runs
- **THEN** the expired connection is closed and a fresh authenticated connection serves the request

#### Scenario: Pool cap
- **GIVEN** `jntlm.pool.max-idle: 2` and two pooled connections
- **WHEN** a third connection is returned to the pool
- **THEN** the least recently pooled connection is closed and the pool holds two connections

#### Scenario: Pooling disabled
- **GIVEN** `jntlm.pool.max-idle: 0`
- **WHEN** a keep-alive exchange completes cleanly
- **THEN** the parent connection is closed instead of pooled

#### Scenario: Invalid pool configuration
- **WHEN** jntlm starts with a negative `jntlm.pool.max-idle` or a non-positive `jntlm.pool.idle-timeout`
- **THEN** startup fails with an error naming the offending property

### Requirement: Efficient tunnel relay
The system SHALL relay `CONNECT` tunnel data in each direction with a reusable buffer of at least
16 KiB, without copying through an intermediate output buffer and without data loss, including
bytes already buffered from the client or parent before the tunnel started.

#### Scenario: Bulk tunnel transfer
- **GIVEN** an established `CONNECT` tunnel to an echo endpoint
- **WHEN** the client sends 8 MiB of random data
- **THEN** the client receives exactly the same 8 MiB back

#### Scenario: Bytes buffered before the tunnel
- **GIVEN** the parent sends its `200` response and the first tunneled bytes in one TCP segment
- **WHEN** the tunnel starts
- **THEN** the client receives those bytes before any later tunnel data

#### Scenario: Close semantics unchanged
- **WHEN** either side of an established tunnel closes its connection
- **THEN** both tunnel connections are closed

### Requirement: Coalesced small writes
The system SHALL send a message's header section together with its fixed-length body of at most
8 KiB to the peer with a single flush, without changing the bytes sent. Larger or chunked bodies
SHALL keep flushing headers before relaying the body.

#### Scenario: Small fixed-length response
- **GIVEN** the parent returns a `200` response with `Content-Length: 512`
- **WHEN** the proxy relays it
- **THEN** the client receives byte-identical headers and body and the output is flushed once for that response

#### Scenario: Large body still streams
- **GIVEN** the parent returns a `Content-Length: 10485760` response
- **WHEN** the proxy relays it
- **THEN** the headers are flushed before the whole body has been received

## MODIFIED Requirements

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

#### Scenario: Stale pooled connection with a forwarded body
- **GIVEN** a pooled parent connection has been closed by the peer
- **WHEN** a client sends a `POST` with a body over it and the parent returns no response
- **THEN** the request is not replayed
- **AND** the client receives `502 Bad Gateway` instead of a silent connection close

### Requirement: Performance regression coverage
The project SHALL provide repeatable performance coverage for keep-alive traffic, body forwarding,
fresh NTLM handshakes, pooling, failover, flag detection, multiple requests on one client
connection, `CONNECT` tunnel throughput, idle-pool eviction, and header parsing.

#### Scenario: Benchmark execution
- **WHEN** the performance benchmark suite runs against an in-process parent fixture
- **THEN** it reports throughput, latency, and allocation or resource observations for each workload

#### Scenario: Correctness under benchmark load
- **WHEN** benchmark workloads run concurrently
- **THEN** all requests complete with correct bodies and status codes and existing protocol tests remain passing

#### Scenario: Tunnel and pool workloads
- **WHEN** the benchmark suite runs
- **THEN** it reports `CONNECT` tunnel throughput for a multi-megabyte echo and the open parent connection count after idle eviction
