# Proposal

## Why

The jntlm listener accepts every client connection without authentication. That is acceptable when
it is bound to `127.0.0.1`, but as soon as `jntlm.listen-address` is opened to other hosts (shared
workstation, container network, small team gateway) anyone who can reach the port can use the
configured corporate NTLM identity. An optional HTTP BASIC proxy authentication gate lets operators
restrict who may use the proxy without changing how jntlm authenticates to the parent.

## What Changes

- Add an optional, **disabled-by-default** BASIC authentication check for incoming client
  connections, configured under a new `jntlm.client-auth.*` property group:
  - `enabled` (default `false`),
  - `realm` (default `jntlm`),
  - `users` — a list of `username` / `password` entries; a password is either plaintext or a
    `{sha256}<hex>` digest so plaintext need not sit in config.
- When enabled, the first request on each client connection (plain HTTP and `CONNECT`) must carry a
  valid `Proxy-Authorization: Basic ...` header; otherwise jntlm replies `407 Proxy Authentication
  Required` with `Proxy-Authenticate: Basic realm="<realm>"` and closes the connection, without
  contacting any parent proxy.
- Once a connection has authenticated, later keep-alive requests on that same TCP connection are
  accepted without re-checking (see Assumptions).
- The client's `Proxy-Authorization` header is never forwarded to the parent proxy (already the
  case today; kept as an explicit requirement).
- Invalid configuration (enabled with no users, blank username, blank password, malformed
  `{sha256}` digest) fails application startup with a clear message.
- Document the new properties in `application.yml` and `README.md`.

No breaking changes: with `enabled: false` (the default) behavior is identical to today.

## Capabilities

### New Capabilities
- `client-authentication`: optional authentication of clients connecting to the jntlm listener
  (configuration, credential verification, 407 challenge behavior, and per-connection scope).

### Modified Capabilities
<!-- None: existing ntlm-flags-detection and proxy-performance requirements are unchanged. -->

## Impact

- **Config:** `JntlmProperties` (new nested `ClientAuth` / `User`), `application.yml` defaults and
  comments, `README.md` configuration table.
- **Server:** `server/ClientConnectionHandler` gains a pre-forward authentication check on the first
  request; `server/ProxyServer` passes the new authenticator to each handler.
- **New component:** a client-side BASIC authenticator (in `server/`) built from properties at
  startup and validated fail-fast.
- **Unchanged:** `proxy/RequestForwarder` (CNTLM `forward_request` port), parent NTLM handshake,
  connection pooling, flags detection.
- **Dependencies:** none (JDK `Base64` / `MessageDigest` only).
- **Tests:** new unit tests for the authenticator and config validation; handler-level tests for
  407 / pass-through behavior.

## Assumptions

- The user was unavailable for clarification; the following defaults were chosen and can be
  revised with `/opsx-update`:
  - Multiple users are supported (a list), which also covers the single-user case.
  - Authentication is scoped to the client TCP connection: the first request authenticates the
    connection, subsequent keep-alive requests on it are trusted. This keeps the CNTLM-ported
    `RequestForwarder` untouched (it reads follow-up requests itself) and matches the fact that the
    peer cannot change mid-connection.
  - On failure jntlm closes the connection after the 407 (avoids draining unknown request bodies);
    standard clients (curl, browsers, Java, npm) reconnect and retry with credentials.
  - Passwords may be plaintext or `{sha256}<hex>` (unsalted SHA-256 of the UTF-8 password); Spring
    property placeholders (e.g. `${JNTLM_CLIENT_PASSWORD}`) remain available for plaintext.

## Out of Scope

- Authentication schemes other than BASIC (Digest, NTLM/Negotiate from clients, mTLS).
- Per-user parent credentials or passing client identity through to the parent (CNTLM
  `NTLMToBasic`-style behavior).
- IP allow/deny lists (CNTLM `Allow`/`Deny`).
- Salted / slow password hashes (bcrypt, argon2) and external user stores.
- Rate limiting or lockout after failed attempts.
- TLS on the listener (BASIC credentials travel in clear text; documented as a caveat).
