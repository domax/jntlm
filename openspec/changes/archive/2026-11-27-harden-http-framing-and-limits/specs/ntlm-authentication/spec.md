# Spec Delta

## Purpose

Defines how jntlm handles the parent proxy's NTLM challenge and failures during parent
authentication so that malformed input fails the handshake cleanly without crashing or leaking
connections.

## ADDED Requirements

### Requirement: Type-2 challenge validation
The system SHALL accept a parent's NTLM Type-2 message only if it is at least 32 bytes, starts with
the `NTLMSSP\0` signature and has message type 2. It SHALL read the target-information block only
when the message is at least 48 bytes and the block lies entirely inside the message. An invalid
challenge SHALL fail the handshake.

#### Scenario: Short challenge
- **WHEN** the parent's `Proxy-Authenticate: NTLM` value decodes to 44 bytes with a valid signature and type 2
- **THEN** the Type-3 message is built without target information and no internal error occurs

#### Scenario: Wrong signature
- **WHEN** the challenge decodes to 64 bytes not starting with `NTLMSSP\0`
- **THEN** the handshake fails as an invalid challenge

#### Scenario: Target-info offset outside message
- **WHEN** the challenge's target-information offset points past the end of the message
- **THEN** the Type-3 message is built without target information and no internal error occurs

### Requirement: Type-3 size is not fixed
The system SHALL build Type-3 messages sized to their content, so that any valid challenge whose
target information fits the NTLM 16-bit length fields produces a complete Type-3 message.

#### Scenario: Large target information
- **WHEN** an NTLMv2 handshake receives a valid challenge with 2000 bytes of target information
- **THEN** a complete Type-3 message containing that target information is sent

### Requirement: Failed handshake response
The system SHALL, when parent authentication fails because of an invalid challenge or an
unreachable or closed parent, close the parent connection and reply `502 Bad Gateway` to the
client if no response bytes were sent yet.

#### Scenario: Invalid challenge
- **WHEN** the parent's 407 carries `Proxy-Authenticate: NTLM AAAA`
- **THEN** the client receives `502 Bad Gateway`
- **AND** the parent connection is closed and not pooled

### Requirement: Internal errors do not leak connections
The system SHALL, on any unexpected internal error while serving a client request, close the
client connection and the parent connection in use, never pool that parent connection, and log the
error at WARN without credentials or authorization header values.

#### Scenario: Unexpected error during forwarding
- **WHEN** an unexpected runtime error occurs while a request is being forwarded
- **THEN** the client connection is closed
- **AND** the parent connection in use is closed and not pooled
- **AND** a WARN log entry is written that contains no `Proxy-Authorization` value
