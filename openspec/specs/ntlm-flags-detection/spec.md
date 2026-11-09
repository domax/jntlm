# ntlm-flags-detection Specification

## Purpose

Lets jntlm find, cache and reuse the NTLM negotiate flags that the parent proxy accepts, so users
do not have to discover and pin `jntlm.flags` by trial and error. When detection is disabled or
fails, jntlm falls back to the explicit or hardcoded flags.

## Requirements

### Requirement: Candidate acceptance by full handshake
The system SHALL accept a candidate flag set only when, on a fresh parent connection, a Type-1 with
those flags gets a 407 reply that carries a valid NTLM Type-2 challenge, and the following Type-3
gets a non-407 reply. Any other outcome SHALL reject the candidate: an I/O error, a timeout, a
closed connection, a missing or invalid challenge, or a 407 reply to the Type-3.

#### Scenario: Parent accepts the candidate
- **GIVEN** a parent proxy that sends a valid Type-2 for flags `0x00088205` and accepts the Type-3
- **WHEN** the system probes with candidate `0x00088205`
- **THEN** the candidate is accepted

#### Scenario: Parent gives no challenge for the candidate
- **GIVEN** a parent proxy that replies 407 without an NTLM challenge to a Type-1 with flags `0xa208b205`
- **WHEN** the system probes with candidate `0xa208b205`
- **THEN** the candidate is rejected and the next candidate is tried on a new connection

#### Scenario: Parent rejects the Type-3
- **GIVEN** a parent proxy that sends a Type-2 but replies 407 to the Type-3
- **WHEN** the system probes with that candidate
- **THEN** the candidate is rejected

#### Scenario: Parent does not require authentication
- **GIVEN** a parent proxy that answers the Type-1 probe with a non-407 reply
- **WHEN** the system probes with the first candidate
- **THEN** that candidate is accepted

### Requirement: Candidate order
The system SHALL try candidates in this order, skipping duplicates. First, the explicit `jntlm.flags`
value if it is non-zero. Second, the hardcoded default for the configured `jntlm.auth` dialect.
Third, reduced variants of that default for the same dialect. The number of candidates SHALL be
bounded.

#### Scenario: Explicit flags are tried first
- **GIVEN** `jntlm.flags` is `0x00088205` and the parent accepts it
- **WHEN** detection runs
- **THEN** `0x00088205` is the first candidate probed and the only one probed

#### Scenario: Hardcoded default tried before variants
- **GIVEN** `jntlm.flags` is unset, `jntlm.auth` is `NTLMV2`, and the parent accepts `0xa208b205`
- **WHEN** detection runs
- **THEN** `0xa208b205` is the first and only candidate probed

#### Scenario: Reduced variant found
- **GIVEN** `jntlm.auth` is `NTLMV2` and the parent accepts only `0x00088205`
- **WHEN** detection runs
- **THEN** `0x00088205` is accepted after the default `0xa208b205` is rejected

### Requirement: Challenge-derived candidates
When a candidate gets a valid Type-2 but its Type-3 is rejected, the system SHALL add a new
candidate next in line. That candidate is the rejected flags masked by the flags the parent
advertised in the Type-2, provided it is non-zero, keeps the dialect's charset flag, and has not
been tried yet.

#### Scenario: Server-advertised flags refine the candidate
- **GIVEN** the parent challenges candidate `0xa208b205` with Type-2 flags `0x00088205` but rejects the Type-3
- **WHEN** detection continues
- **THEN** the next candidate probed is `0x00088205`

### Requirement: Cached flags for parent connections
After detection, the system SHALL use the accepted flags for the Type-1 on every new parent
connection, with no further probing, until the cache is invalidated. Reused authenticated
connections are not affected.

#### Scenario: Subsequent requests reuse detected flags
- **GIVEN** detection accepted `0x00088205`
- **WHEN** a later client request needs a new parent connection
- **THEN** the Type-1 carries flags `0x00088205` and no detection probes are sent

### Requirement: Fallback when detection fails
If no candidate is accepted, the system SHALL use the configured dialect's hardcoded default flags
for parent connections and log a warning. The client request SHALL then be forwarded with the
current behavior.

#### Scenario: All candidates rejected
- **GIVEN** `jntlm.auth` is `NTLMV2` and the parent rejects every candidate
- **WHEN** detection finishes
- **THEN** a warning is logged and new parent connections use flags `0xa208b205`

#### Scenario: Explicit flags rejected and nothing else works
- **GIVEN** `jntlm.flags` is `0x00000205` and the parent rejects every candidate
- **WHEN** detection finishes
- **THEN** new parent connections use the dialect default rather than `0x00000205`

### Requirement: Detection disabled
When `jntlm.detect.enabled` is `false`, the system SHALL send no detection probes. It SHALL use
the explicit `jntlm.flags` when non-zero, otherwise the dialect's hardcoded default, matching
pre-change behavior.

#### Scenario: Detection switched off with explicit flags
- **GIVEN** `jntlm.detect.enabled` is `false` and `jntlm.flags` is `0x00088205`
- **WHEN** a client request needs a new parent connection
- **THEN** no probe connections are opened and the Type-1 carries flags `0x00088205`

### Requirement: Eager detection with a probe URL
When `jntlm.detect.probe-url` is set, the system SHALL start detection at startup without blocking
the listener. An `http` URL SHALL be probed with a body-less `GET`. An `https` URL SHALL be probed
with `CONNECT host:port`, using port 443 by default.

#### Scenario: Startup detection with http probe URL
- **GIVEN** `jntlm.detect.probe-url` is `http://example.com/`
- **WHEN** jntlm starts
- **THEN** detection probes the parent with `GET http://example.com/` before any client request arrives

#### Scenario: Startup detection with https probe URL
- **GIVEN** `jntlm.detect.probe-url` is `https://example.com/`
- **WHEN** jntlm starts
- **THEN** detection probes the parent with `CONNECT example.com:443`

### Requirement: Lazy detection on first request
When no flags are cached and no detection is running, a client request that needs a new parent
connection SHALL first trigger detection. The probe SHALL be a body-less copy of that request:
`CONNECT` stays `CONNECT` and other methods become `GET`. Only after detection SHALL the request be
forwarded.

#### Scenario: First POST request triggers a GET probe
- **GIVEN** no probe URL is configured and no flags are cached
- **WHEN** the first client request is `POST http://example.com/api` with a body
- **THEN** detection probes with a body-less `GET http://example.com/api` and the original POST is then forwarded once with its body

### Requirement: Single detection at a time
Only one detection SHALL run at a time. Requests that need flags while it runs SHALL wait for its
result instead of starting their own.

#### Scenario: Concurrent first requests
- **GIVEN** no flags are cached
- **WHEN** two client requests arrive at the same time
- **THEN** only one detection sequence is run and both requests use its result

### Requirement: Cache invalidation
The system SHALL clear the cache and detect again on the next request when the active parent
changes. It SHALL do the same when a fresh handshake using the cached flags (detected or fallback) is
rejected with 407, unless the last detection was less than the cool-down interval ago.

#### Scenario: Parent failover
- **GIVEN** flags were detected for parent A
- **WHEN** parent A fails and the system switches to parent B
- **THEN** the next request that needs a new connection runs detection against parent B

#### Scenario: Cached flags start failing
- **GIVEN** cached flags and a last detection older than the cool-down interval
- **WHEN** a fresh handshake with those flags gets 407 after the Type-3
- **THEN** the client gets the current 407 response and the next request runs detection again

#### Scenario: Rejection within cool-down
- **GIVEN** detection finished less than the cool-down interval ago
- **WHEN** a fresh handshake with the cached flags is rejected
- **THEN** the cache is kept and no new detection starts

### Requirement: Detection result logging
The system SHALL log the accepted flags at INFO, as `0x`-prefixed 8-digit hex, together with the
parent proxy. It SHALL log each rejected candidate and its reason at DEBUG.

#### Scenario: Successful detection log
- **WHEN** detection accepts flags `0x00088205` for parent `proxy.example.com:8080`
- **THEN** an INFO log line contains `0x00088205` and `proxy.example.com:8080`
