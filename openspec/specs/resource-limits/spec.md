# resource-limits Specification

## Purpose

Bounds the memory, file descriptors and time a single client or parent connection can consume, so
that slow, idle or abusive peers cannot exhaust jntlm's resources.

## Requirements

### Requirement: Header section size limit
The system SHALL limit a message's header section (start line, header lines and trailers) to
`jntlm.limits.max-header-bytes` bytes (default 131072) and `jntlm.limits.max-header-count` header
lines (default 256), in addition to the existing 64 KiB per-line limit. A client request exceeding
a limit SHALL receive `431 Request Header Fields Too Large`; a parent response exceeding it SHALL
cause `502`.

#### Scenario: Too many header lines
- **GIVEN** default limits
- **WHEN** a client sends a request with 257 header lines
- **THEN** the client receives `431 Request Header Fields Too Large` with `Connection: close`
- **AND** nothing is forwarded to the parent

#### Scenario: Header section too large
- **GIVEN** `jntlm.limits.max-header-bytes: 1024`
- **WHEN** a client sends a request whose header section is 2000 bytes
- **THEN** the client receives `431` and the connection is closed

#### Scenario: Oversized parent response headers
- **GIVEN** default limits
- **WHEN** the parent replies with 300 header lines
- **THEN** the client receives `502 Bad Gateway` and the parent connection is closed

#### Scenario: Limit applies before client authentication
- **GIVEN** client authentication is enabled
- **WHEN** an unauthenticated client sends a request with 257 header lines
- **THEN** the client receives `431` and no credential check is performed

### Requirement: Client idle timeout
The system SHALL close a client connection when no byte is received from the client for
`jntlm.limits.client-idle-timeout` (default `300s`, `0` disables) while jntlm is waiting to read a
request's headers or body.

#### Scenario: Idle keep-alive client
- **GIVEN** `jntlm.limits.client-idle-timeout: 1s`
- **WHEN** a client completes one request and then sends nothing for 2 seconds
- **THEN** jntlm closes the client connection

#### Scenario: Timeout disabled
- **GIVEN** `jntlm.limits.client-idle-timeout: 0`
- **WHEN** a client stays idle between requests
- **THEN** jntlm does not close the connection for inactivity

### Requirement: Parent read timeout
The system SHALL abort an exchange when no byte is received from the parent proxy for
`jntlm.limits.parent-read-timeout` (default `600s`, `0` disables) while jntlm is waiting for the
parent's response headers or body. If no response bytes were relayed yet the client SHALL receive
`504 Gateway Timeout`; the parent connection SHALL be closed and not pooled.

#### Scenario: Parent never answers
- **GIVEN** `jntlm.limits.parent-read-timeout: 1s`
- **WHEN** the parent accepts a request but sends no response for 2 seconds
- **THEN** the client receives `504 Gateway Timeout`
- **AND** the parent connection is closed

#### Scenario: Parent stalls mid-body
- **GIVEN** `jntlm.limits.parent-read-timeout: 1s`
- **WHEN** the parent stops sending in the middle of a response body for 2 seconds
- **THEN** the client connection is closed and the parent connection is not pooled

### Requirement: Tunnel idle timeout
The system SHALL apply `jntlm.limits.tunnel-idle-timeout` (default `0` = no timeout) to established
`CONNECT` tunnels instead of the client idle and parent read timeouts. When set, a tunnel with no
bytes in either direction for that duration SHALL be closed.

#### Scenario: Long-lived idle tunnel by default
- **GIVEN** default limits and `jntlm.limits.client-idle-timeout: 1s`
- **WHEN** a `CONNECT` tunnel carries no data for 2 seconds and then the client sends bytes
- **THEN** the tunnel is still open and the bytes reach the parent

#### Scenario: Tunnel idle timeout enabled
- **GIVEN** `jntlm.limits.tunnel-idle-timeout: 1s`
- **WHEN** a `CONNECT` tunnel carries no data in either direction for 2 seconds
- **THEN** both tunnel connections are closed

### Requirement: Concurrent client connection limit
The system SHALL serve at most `jntlm.limits.max-client-connections` client connections at once
(default 1024, `0` = unlimited). A connection accepted above the limit SHALL receive
`503 Service Unavailable` with `Connection: close` and be closed without reading a request or
contacting the parent proxy.

#### Scenario: Limit reached
- **GIVEN** `jntlm.limits.max-client-connections: 2` and two open client connections
- **WHEN** a third client connects
- **THEN** it receives `503 Service Unavailable` and is closed
- **AND** no parent connection is opened for it

#### Scenario: Capacity is released
- **GIVEN** `jntlm.limits.max-client-connections: 2` and one of two open connections closes
- **WHEN** a new client connects
- **THEN** it is served normally

### Requirement: Limits configuration validation
The system SHALL fail startup when a `jntlm.limits.*` value is negative, or when `max-header-bytes`
or `max-header-count` is zero, with a message naming the offending property.

#### Scenario: Negative timeout
- **WHEN** jntlm starts with `jntlm.limits.client-idle-timeout: -1s`
- **THEN** startup fails with an error naming `jntlm.limits.client-idle-timeout`

#### Scenario: Defaults
- **WHEN** jntlm starts without any `jntlm.limits.*` setting
- **THEN** it starts with the documented default limits
