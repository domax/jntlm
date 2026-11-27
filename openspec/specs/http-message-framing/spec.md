# http-message-framing Specification

## Purpose

Defines how jntlm parses, validates, frames and relays HTTP/1.x messages between clients and the
parent proxy so that message boundaries are never ambiguous and pooled parent connections never
carry another client's bytes.

## Requirements

### Requirement: Malformed client requests are rejected
The system SHALL reject a client request whose start line or header section is malformed by
replying `400 Bad Request` with `Connection: close` and closing the client connection, without
forwarding any part of that request to the parent proxy. Clean EOF before any byte SHALL close the
connection silently.

#### Scenario: Whitespace before colon
- **WHEN** a client sends a request containing the header line `Content-Length : 5`
- **THEN** the client receives `400 Bad Request` with `Connection: close`
- **AND** the parent proxy receives no bytes for that request

#### Scenario: Header line without colon
- **WHEN** a client sends a header line `X-Broken` with no colon
- **THEN** the client receives `400 Bad Request` and the connection is closed

#### Scenario: Obsolete line folding
- **WHEN** a header line begins with a space or horizontal tab
- **THEN** the client receives `400 Bad Request` and the connection is closed

#### Scenario: Bare carriage return
- **WHEN** a start line or header line contains a CR not immediately followed by LF
- **THEN** the client receives `400 Bad Request` and the connection is closed

#### Scenario: Malformed request line
- **WHEN** a client sends `GARBAGE` as the first line
- **THEN** the client receives `400 Bad Request` and the connection is closed

#### Scenario: Client closes without sending
- **WHEN** a client opens a connection and closes it without sending bytes
- **THEN** no response is written and the connection is closed

### Requirement: Malformed parent responses are rejected
The system SHALL treat a parent response whose status line or header section is malformed (same
rules as for client requests) as a gateway failure: the client receives `502 Bad Gateway` and the
parent connection is closed and not pooled.

#### Scenario: Parent header with whitespace before colon
- **WHEN** the parent replies with the header line `Transfer-Encoding : chunked`
- **THEN** the client receives `502 Bad Gateway`
- **AND** the parent connection is closed and not pooled

### Requirement: Content-Length validation
The system SHALL accept `Content-Length` only as one or more decimal digits fitting a signed 64-bit
value. Multiple `Content-Length` values (repeated lines or comma lists) SHALL be accepted only if
all are identical, and SHALL then be forwarded as a single field. Any other value SHALL be a framing
error: `400` for client requests, `502` for parent responses.

#### Scenario: Negative length from client
- **WHEN** a client sends `Content-Length: -5`
- **THEN** the client receives `400 Bad Request` and nothing is forwarded

#### Scenario: Non-numeric length from client
- **WHEN** a client sends `Content-Length: abc`
- **THEN** the client receives `400 Bad Request`

#### Scenario: Conflicting duplicate lengths
- **WHEN** a client sends `Content-Length: 5` and `Content-Length: 6`
- **THEN** the client receives `400 Bad Request`

#### Scenario: Identical duplicate lengths
- **WHEN** a client sends `Content-Length: 5` twice with a 5-byte body
- **THEN** the parent receives exactly one `Content-Length: 5` field and the 5-byte body

#### Scenario: Invalid length from parent
- **WHEN** the parent replies with `Content-Length: 12x`
- **THEN** the client receives `502 Bad Gateway`
- **AND** the parent connection is closed and not pooled

### Requirement: Transfer-Encoding validation
The system SHALL treat a message as chunked only when the last comma-separated
`Transfer-Encoding` token equals `chunked` (case-insensitive). A client request with
`Transfer-Encoding` whose final coding is not `chunked`, or with both `Transfer-Encoding` and
`Content-Length`, SHALL be rejected with `400`.

#### Scenario: Request with both framings
- **WHEN** a client sends both `Transfer-Encoding: chunked` and `Content-Length: 10`
- **THEN** the client receives `400 Bad Request` and nothing is forwarded

#### Scenario: Substring is not a token
- **WHEN** a client sends `Transfer-Encoding: xchunked`
- **THEN** the client receives `400 Bad Request`

#### Scenario: Valid chunked request
- **WHEN** a client sends `Transfer-Encoding: gzip, chunked` with a valid chunked body
- **THEN** the parent receives the same chunk framing, chunk data and trailers

### Requirement: Response with both framings
The system SHALL treat a parent response carrying both `Transfer-Encoding: chunked` and
`Content-Length` as chunked, SHALL remove `Content-Length` before relaying it to the client, and
SHALL NOT pool the parent connection afterwards.

#### Scenario: Parent sends both
- **WHEN** the parent replies with `Transfer-Encoding: chunked` and `Content-Length: 3` and a valid chunked body
- **THEN** the client receives the chunked body without a `Content-Length` header
- **AND** the parent connection is closed after the exchange

### Requirement: Request body framing is independent of method
The system SHALL determine whether a client request has a body solely from its `Transfer-Encoding`
and `Content-Length` fields, for every method including `GET` and `HEAD`.

#### Scenario: GET with a body
- **WHEN** a client sends `GET` with `Content-Length: 4` and body `abcd`, followed by a second request on the same connection
- **THEN** the parent receives the `GET` with the 4-byte body
- **AND** the second request is parsed starting after `abcd`

### Requirement: Strict chunk parsing
The system SHALL accept a chunk-size line only as 1 to 16 hexadecimal digits optionally followed by
chunk extensions, and SHALL require CRLF after each chunk's data. A violation or premature EOF
SHALL abort the exchange: the client connection is closed and the parent connection is closed and
not pooled.

#### Scenario: Invalid chunk size from parent
- **WHEN** a parent's chunked response contains the size line `zz`
- **THEN** the client connection is closed after the bytes already relayed
- **AND** the parent connection is not returned to the pool

#### Scenario: Chunk data not followed by CRLF
- **WHEN** a chunk's data is followed by bytes other than CRLF
- **THEN** the exchange is aborted and neither connection is reused

### Requirement: Truncated bodies are not reused
The system SHALL treat EOF before a fixed-length body is complete as an aborted exchange: the
other side's connection is closed and the parent connection is not pooled.

#### Scenario: Parent closes mid-body
- **WHEN** the parent sends `Content-Length: 100` and closes after 40 bytes
- **THEN** the client receives the 40 bytes and its connection is then closed
- **AND** no parent connection is added to the pool

### Requirement: Connection header tokens
The system SHALL interpret `Connection` and `Proxy-Connection` values as comma-separated,
case-insensitive tokens when deciding keep-alive or close.

#### Scenario: Keep-alive token in list
- **WHEN** the parent replies with `Proxy-Connection: Keep-Alive, Upgrade` to an HTTP/1.1 request
- **THEN** the parent connection is treated as persistent

#### Scenario: Token substring does not match
- **WHEN** the parent replies with `Proxy-Connection: not-keep-alive`
- **THEN** the parent connection is not treated as persistent

### Requirement: Pool only cleanly framed exchanges
The system SHALL return a parent connection to the pool only when the request and response were
both completely transferred with unambiguous framing. A response that has a body-capable status but
neither `Content-Length` nor `Transfer-Encoding` SHALL NOT leave its parent connection pooled.

#### Scenario: Unframed response
- **WHEN** the parent replies `200` with `Content-Type: text/plain` and neither `Content-Length` nor `Transfer-Encoding`
- **THEN** the response is relayed as before
- **AND** the parent connection is closed instead of pooled

#### Scenario: Cleanly framed keep-alive exchange
- **WHEN** an authenticated exchange completes with `Content-Length` framing and `Proxy-Connection: keep-alive`
- **THEN** the parent connection is returned to the pool

### Requirement: Header fields are preserved
The system SHALL preserve every received header field line, including repeated names with identical
values, in received order, except for fields the proxy intentionally modifies or removes.

#### Scenario: Repeated identical Set-Cookie
- **WHEN** the parent replies with two identical `Set-Cookie: a=1` lines
- **THEN** the client receives both lines

#### Scenario: Interleaved header order
- **WHEN** a message contains `A: 1`, `B: 2`, `A: 3` in that order
- **THEN** they are forwarded in the order `A: 1`, `B: 2`, `A: 3`
