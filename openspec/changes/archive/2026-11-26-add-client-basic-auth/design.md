# Design

## Context

See `proposal.md` (Why) and `specs/client-authentication/spec.md` (requirements).

Relevant current structure:

- `server/ProxyServer` accepts sockets and runs one `ClientConnectionHandler` per connection on a
  virtual thread. It is constructed by Spring (`@RequiredArgsConstructor`) from `JntlmProperties`,
  `RequestForwarder` and the `clientExecutor` bean.
- `server/ClientConnectionHandler.run()` reads the first request with `HttpIo.recvHeaders` and hands
  it to `RequestForwarder.forward(...)`. Follow-up keep-alive requests are read **either** by the
  handler loop (after a `DONE` result) **or** inside `RequestForwarder`'s inner `do/while`, which
  calls `HttpIo.recvHeaders(client.in())` directly while a parent connection is pinned.
- `RequestForwarder` (port of CNTLM `forward_request`) already removes the client's
  `Proxy-Authorization` header in loop 0 before talking to the parent.
- `JntlmConfig` builds startup beans from `JntlmProperties` and is the existing place for
  config-derived objects (e.g. `globalCredentials`). Tests wire components manually
  (`new RequestForwarder(manager, pool, auth, creds, resolver)`).
- CNTLM has no equivalent feature (its `NTLMToBasic` passes client credentials to the parent, which
  is a different behavior), so there is no C function to port; this is a jntlm-only addition and
  must be clearly marked as such in Javadoc.

## Goals / Non-Goals

**Goals:**
- Gate client connections behind BASIC credentials with zero behavior change when disabled.
- Keep the CNTLM-ported `RequestForwarder` and parent NTLM flow untouched.
- Constant-time credential verification; no secrets in logs.
- Fail fast on invalid configuration.

**Non-Goals:**
- Re-validating every keep-alive request (see Decision 2).
- Draining request bodies on rejection to keep the connection alive.

## Decisions

### 1. New `server/ClientAuthenticator` component, built in `JntlmConfig`

A small final class in `server/` exposing:

- `boolean enabled()` (fluent accessor),
- `Result check(HttpMessage request)` → accepted / rejected (with optional username for logging),
- `void sendChallenge(Endpoint client, HttpMessage request) throws IOException` writing the 407.

A static factory `ClientAuthenticator.from(JntlmProperties.ClientAuth)` validates config and throws
`IllegalStateException` with a descriptive message on any rule in the "Invalid configuration fails
startup" requirement. A `@Bean ClientAuthenticator clientAuthenticator(JntlmProperties)` in
`JntlmConfig` calls it, so startup fails during context refresh. A `ClientAuthenticator.disabled()`
factory returns an instance with `enabled() == false` (used when `enabled` is false — validation is
skipped entirely — and by tests).

*Alternatives:* Spring `@Validated` + Bean Validation on properties — rejected: adds a dependency
and cannot express the digest/duplicate rules cleanly. Putting logic in `RequestForwarder` —
rejected: it is a faithful CNTLM port and the "parity" directive discourages non-CNTLM logic there.

### 2. Authenticate the first request per connection, in `ClientConnectionHandler`

`ClientConnectionHandler` gets a third final field `ClientAuthenticator clientAuth`. In `run()`, a
local `authenticated` flag starts as `!clientAuth.enabled()`. For each request read by the handler
loop, if not yet authenticated: call `check`; on rejection log WARN, `sendChallenge`, and `break`
(the existing `finally` closes the socket); on success set `authenticated = true` and continue to
forwarding unchanged.

Because the first request on any connection always goes through the handler, and `RequestForwarder`
only reads further requests on an already-accepted connection, this enforces the connection-scoped
requirement without touching `RequestForwarder`.

*Alternative:* per-request checks — would require injecting the authenticator into
`RequestForwarder`'s inner read path (changing its constructor and every test wiring) and
deviating from the CNTLM control flow. The peer of a TCP connection cannot change, so per-request
checks add little security for a local proxy. Recorded as an assumption in the proposal.

### 3. Credential storage and comparison

At startup every configured password is normalized to a 32-byte SHA-256 digest:
plaintext → `SHA-256(UTF-8 bytes)`; `{sha256}<hex>` (prefix case-insensitive) → `HexFormat`
parse. Users are stored in an immutable `Map<String, byte[]>`.

Verification of `Proxy-Authorization`:
1. Header absent, scheme not `Basic` (case-insensitive), or base64 invalid → reject (no username).
2. Decode base64 → UTF-8 string; split at the **first** `:`; no colon → reject.
3. Compute `SHA-256(password)`; look up the user's digest, or a fixed dummy digest when unknown;
   compare with `MessageDigest.isEqual` (constant time) and accept only if the user exists **and**
   digests match. This keeps timing uniform for unknown users.

Only JDK classes (`Base64`, `MessageDigest`, `HexFormat`) are used. Plaintext passwords are not
retained after startup.

*Alternative:* bcrypt via `spring-security-crypto` — out of scope (new dependency); the `{prefix}`
format leaves room to add schemes later.

### 4. 407 response format

Built via `HttpMessage.newResponse(proto, 407, "Proxy Authentication Required")` where `proto` is the
request's protocol (fallback `HTTP/1.1`) and sent with `HttpIo.sendHeaders`, followed by a small
HTML body like `ErrorPages.send502`. Headers:
`Proxy-Authenticate: Basic realm="<realm>"`,
`Content-Type: text/html`, `Content-Length: <n>`, `Connection: close`, `Proxy-Connection: close`.
Output is flushed before the handler closes the socket. The request body (if any) is not read.

*Alternative:* keep the connection alive and drain the body — rejected: requires body-length
handling for unauthenticated input and widens the attack surface; clients reconnect on close.

### 5. Configuration shape

```yaml
jntlm:
  client-auth:
    enabled: false
    realm: jntlm
    users:
      - username: alice
        password: "${JNTLM_ALICE_PASSWORD}"
      - username: bob
        password: "{sha256}5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

`JntlmProperties` gets `private ClientAuth clientAuth = new ClientAuth();` with nested `@Data`
classes `ClientAuth { boolean enabled = false; String realm = "jntlm"; List<User> users = new
ArrayList<>(); }` and `User { String username = ""; String password = ""; }`. The `User` class must
not expose the password in `toString()` (use `@ToString.Exclude`).

### 6. Logging

- Startup (INFO): `Client authentication enabled for N user(s), realm '<realm>'` — or nothing when
  disabled.
- Rejection (WARN): `Rejected client {addr}: {reason}[ (user '{name}')]` with `reason` one of
  `missing credentials`, `unsupported scheme`, `malformed credentials`, `invalid credentials`.
- Success (DEBUG): `Authenticated client {addr} as '{name}'`.
Never log the header value or password.

## Risks / Trade-offs

- [BASIC sends credentials in base64 clear text] → Document in README that it protects against
  casual use on trusted networks only; recommend keeping `listen-address` restricted. TLS is out of
  scope.
- [Unsalted SHA-256 digests are brute-forceable if config leaks] → Document; still better than
  plaintext; prefix format allows a stronger scheme later.
- [Connection-scoped auth: a long-lived authenticated connection stays usable after a config
  change] → Config is only read at startup anyway; restart closes all connections.
- [Rejected POST/PUT bodies are not drained] → Connection is closed, so no desync is possible.
- [Clients that never send credentials preemptively] → They receive 407 + close and retry on a new
  connection; standard behavior for curl, browsers, Java `HttpClient`, npm. Verify manually with
  `curl -x http://user:pass@127.0.0.1:3128`.
- [NtlmFlagsResolver probe at startup] → Unaffected; it talks to the parent directly, not through
  the listener.

## Migration Plan

Purely additive and disabled by default; no migration. Rollback: set
`jntlm.client-auth.enabled: false` (or remove the block) and restart.
