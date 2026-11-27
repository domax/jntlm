# client-authentication Specification

## Purpose

Lets operators optionally require HTTP BASIC proxy authentication from clients connecting to the
jntlm listener, so only authorized users can use the configured corporate NTLM identity.

## Requirements

### Requirement: Client authentication is disabled by default
The system SHALL accept client requests without any client authentication when
`jntlm.client-auth.enabled` is `false` or not set, behaving exactly as before this capability.

#### Scenario: No client-auth configuration
- **GIVEN** no `jntlm.client-auth` properties are configured
- **WHEN** a client sends `GET http://example.com/` without a `Proxy-Authorization` header
- **THEN** the request is forwarded to the parent proxy and the parent's response is relayed

#### Scenario: Explicitly disabled with users listed
- **GIVEN** `jntlm.client-auth.enabled` is `false` and `users` contains `alice`
- **WHEN** a client sends a request without credentials
- **THEN** the request is forwarded normally

### Requirement: Configured users
When client authentication is enabled, the system SHALL accept credentials only for entries in
`jntlm.client-auth.users`, each having a `username` and a `password`. Usernames SHALL be compared
case-sensitively. A password SHALL be either plaintext or `{sha256}` followed by the 64-hex-digit
SHA-256 digest of the UTF-8 password (prefix and hex digits case-insensitive).

#### Scenario: Plaintext password matches
- **GIVEN** user `alice` with password `s3cret`
- **WHEN** a client sends `Proxy-Authorization: Basic` with `alice:s3cret`
- **THEN** the request is accepted

#### Scenario: SHA-256 password matches
- **GIVEN** user `bob` with password `{sha256}` + hex SHA-256 of `pa:ss`
- **WHEN** a client sends `Proxy-Authorization: Basic` with `bob:pa:ss`
- **THEN** the request is accepted (the password is everything after the first colon)

#### Scenario: Username case differs
- **GIVEN** user `alice` with password `s3cret`
- **WHEN** a client sends credentials `Alice:s3cret`
- **THEN** the request is rejected with 407

### Requirement: Invalid configuration fails startup
When client authentication is enabled, the system SHALL refuse to start, with an error naming the
problem, if `users` is empty, any username is blank or contains `:`, any password is blank, a
`{sha256}` digest is not 64 hex digits, a username appears more than once, or `realm` is blank or
contains `"`, `\` or control characters.

#### Scenario: Enabled without users
- **GIVEN** `jntlm.client-auth.enabled` is `true` and `users` is empty
- **WHEN** the application starts
- **THEN** startup fails with a message stating that at least one user is required

#### Scenario: Malformed digest
- **GIVEN** a user whose password is `{sha256}abc`
- **WHEN** the application starts
- **THEN** startup fails with a message identifying that user's password digest as invalid

#### Scenario: Disabled with invalid users
- **GIVEN** `enabled` is `false` and a user has a blank password
- **WHEN** the application starts
- **THEN** startup succeeds and no client authentication is performed

### Requirement: Unauthenticated connection is challenged
When client authentication is enabled, the system SHALL answer the first request on a client
connection that lacks valid BASIC credentials with `407 Proxy Authentication Required`, a
`Proxy-Authenticate: Basic realm="<realm>"` header, and `Connection: close`, then close the
connection. The parent proxy SHALL NOT be contacted.

#### Scenario: Missing credentials
- **GIVEN** client authentication is enabled with realm `jntlm`
- **WHEN** a client sends `GET http://example.com/` without `Proxy-Authorization`
- **THEN** the client receives status 407 with `Proxy-Authenticate: Basic realm="jntlm"`
- **AND** the connection is closed and no parent connection is opened

#### Scenario: Wrong password
- **GIVEN** user `alice` with password `s3cret`
- **WHEN** a client sends credentials `alice:wrong`
- **THEN** the client receives status 407 and the connection is closed

#### Scenario: Unsupported scheme or malformed header
- **WHEN** a client sends `Proxy-Authorization: NTLM TlRMTVNT...` or `Basic !!notbase64!!`
- **THEN** the client receives status 407 and the connection is closed

#### Scenario: CONNECT without credentials
- **WHEN** a client sends `CONNECT example.com:443` without credentials
- **THEN** the client receives status 407, no tunnel is established, and the connection is closed

#### Scenario: Custom realm
- **GIVEN** `jntlm.client-auth.realm` is `Corp Gateway`
- **WHEN** an unauthenticated request arrives
- **THEN** the 407 carries `Proxy-Authenticate: Basic realm="Corp Gateway"`

### Requirement: Authentication is scoped to the client connection
When the first request on a client connection carries valid credentials, the system SHALL forward
it and SHALL accept all later requests on the same TCP connection without re-checking credentials.
A new client connection SHALL be authenticated again.

#### Scenario: Keep-alive requests after authentication
- **GIVEN** a client connection whose first request carried valid credentials
- **WHEN** the client sends a second request on the same connection without `Proxy-Authorization`
- **THEN** the second request is forwarded normally

#### Scenario: New connection must authenticate
- **GIVEN** a previous connection from the same client authenticated successfully
- **WHEN** the client opens a new connection and sends a request without credentials
- **THEN** the client receives status 407

#### Scenario: Authenticated CONNECT
- **GIVEN** valid credentials on a `CONNECT example.com:443` request
- **WHEN** the parent accepts the tunnel
- **THEN** the client receives the parent's 200 and bytes are relayed in both directions

### Requirement: Client credentials are not forwarded
The system SHALL NOT forward the client's `Proxy-Authorization` header to the parent proxy,
regardless of whether client authentication is enabled.

#### Scenario: Authenticated request reaches parent
- **GIVEN** client authentication is enabled and a client sends valid BASIC credentials
- **WHEN** the request is forwarded to the parent
- **THEN** the parent receives only jntlm's NTLM `Proxy-Authorization` header, never the client's
  BASIC header

### Requirement: Secrets are not logged
The system SHALL NOT log client passwords or the raw `Proxy-Authorization` value. A rejected
attempt SHALL be logged at WARN with the client address and, when decodable, the username.

#### Scenario: Failed attempt logging
- **WHEN** a client at `10.0.0.5` sends credentials `alice:wrong`
- **THEN** a WARN log entry names `10.0.0.5` and `alice` and contains neither `wrong` nor the
  base64 header value

### Requirement: Open-relay exposure warning
The system SHALL log a WARN at startup when the listener is bound to an address that is not a
loopback address (including the wildcard address) while client authentication is disabled. The
warning SHALL name the bound address and suggest enabling `jntlm.client-auth.enabled` or binding to
`127.0.0.1`. Startup SHALL still succeed.

#### Scenario: Wildcard bind without client auth
- **GIVEN** `jntlm.listen-address: 0.0.0.0` and client authentication disabled
- **WHEN** jntlm starts
- **THEN** a WARN log entry names `0.0.0.0` and mentions `jntlm.client-auth.enabled`
- **AND** the listener starts normally

#### Scenario: Loopback bind
- **GIVEN** `jntlm.listen-address: 127.0.0.1` and client authentication disabled
- **WHEN** jntlm starts
- **THEN** no exposure warning is logged

#### Scenario: Non-loopback bind with client auth
- **GIVEN** `jntlm.listen-address: 0.0.0.0` and client authentication enabled
- **WHEN** jntlm starts
- **THEN** no exposure warning is logged
