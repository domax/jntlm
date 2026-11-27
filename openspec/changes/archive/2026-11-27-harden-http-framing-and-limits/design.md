<!--suppress MarkdownUnresolvedLinkLabel -->
## Context

jntlm sits between local clients and a corporate parent proxy, so it parses HTTP in both
directions with hand-written code in `http/` (`HttpIo`, `HttpHeaders`, `HttpMessage`). That code
is a faithful port of CNTLM, and it inherits CNTLM's lenient parsing:

- `Content-Length` goes through `Long.parseLong` and accepts signs and duplicates.
- Any `Transfer-Encoding` value containing `chunked` is chunked, and TE+CL in a request is
  forwarded as-is.
- Header lines with whitespace before the colon, or with no colon, are accepted.
- `HttpHeaders` keys a map by lowercase name and stores values in a `LinkedHashSet`, which
  dedupes identical values and regroups headers.
- `containsToken` is a substring match, so `Connection: notclose` counts as `close`.
- A body cut short by EOF ends silently in `dataTransfer`, and the connection can still be pooled.
- GET/HEAD requests are always treated as body-less, so a body sent with them is read as the next
  request.

These are request-smuggling and desync vectors for a proxy.

Resources are also unbounded:

- No socket timeouts on client or parent sockets.
- No limit on header count or size beyond the 64 KiB line limit.
- No limit on concurrent connections. Virtual threads make each connection cheap, but buffers
  (2 × 8 KiB per endpoint) and FDs still add up.

On the NTLM side:

- `NtlmMessages.type3Response` reads `challenge[44..47]` when only `challenge.length > 40` was
  checked, so a 41–47 byte challenge throws `ArrayIndexOutOfBoundsException`.
- Type-3 is written into a fixed 1024-byte buffer, so a large target-info overflows it.
- `ClientConnectionHandler` catches only `IOException`, so such runtime errors escape the handler
  and skip the parent-connection cleanup in `RequestForwarder`.

Constraints:

- CNTLM parity is the default (AGENTS.md). Every deviation must be deliberate and marked
  "Not in CNTLM" in Javadoc.
- The existing integration tests (`MockParentProxy`) and the benchmark must keep passing.

## Goals / Non-Goals

**Goals:**
- Reject ambiguous or malformed framing with fixed, testable responses (400/431/502/504).
- Never pool a parent connection unless the exchange on it was cleanly framed and complete.
- Bound per-connection memory, idle time and concurrent connections, with configurable defaults
  that keep normal browser/CLI/IDE traffic working.
- Make the NTLM Type-2/Type-3 code safe for any challenge input.
- Warn about open-relay exposure; harden the CI supply chain.

**Non-Goals:**
- Full RFC 9110/9112 conformance (e.g. `Expect: 100-continue`, half-close in tunnels, trailers
  semantics, request-target validation).
- Performance work on pool/tunnel/readLine (change `optimize-pool-and-tunnel`).
- Stronger password hashing for client BASIC auth (PBKDF2) — separate change if wanted.
- Fixing CNTLM's NT-response offset quirk or any other NTLM wire behavior that works today.

## Decisions

### D1. `HttpProtocolException extends IOException` carries the reply status
Violations in `HttpIo`/`HttpHeaders` throw `HttpProtocolException(status, reason)`.

- Because it is an `IOException`, every existing `catch (IOException)` path still closes
  connections correctly. No call site can accidentally ignore the new type.
- The client-facing sites map the status to a reply:
  - `ClientConnectionHandler` request-header read: 400 or 431.
  - `RequestForwarder`, when parent headers fail: 502.
- The error page is sent only if nothing has been written to the client yet. Otherwise the client
  is just closed.

Alternative: return error codes or flags from `recvHeaders`. Rejected: this touches every caller
and is easy to miss.

### D2. `HttpHeaders` becomes an ordered entry list
Replace `LinkedHashMap<String, InnerHeader>` with an `ArrayList<Entry(name, value)>`. Lookups scan
the list. Messages have tens of headers, so a linear scan is as fast as a hash lookup and
allocates less.

- `add` appends.
- `modify` replaces the first match in place and removes later matches (CNTLM `hlist_mod`, which
  the Javadoc already claims).
- `remove` deletes all matches.
- `get` returns the first match.
- `getAll` returns all matches in order.
- `containsToken(name, token)` splits every matching value on `,`, trims, and compares
  case-insensitively. Not in CNTLM: `hlist_subcmp` is a substring match. Deliberate deviation.
- `HttpMessage.copy()` uses `headers.copy()`.

### D3. Framing rules (pure functions in `HttpIo`)
- **Content-Length:** `^[0-9]{1,18}$` after trimming. Multiple CL fields or comma lists are
  collapsed if all values are equal. Otherwise the message is invalid: 400 for a request, 502 for
  a response.
- **Transfer-Encoding:** the final coding must be `chunked`. For any other final coding, a request
  gets 400; a response is read until close and not pooled (RFC 9112 §6.3).
- **TE and CL both present:**
  - Request: 400. jntlm cannot know how the parent will frame it.
  - Response: chunked wins, CL is removed before relaying, and the parent connection is not pooled.
- **Request body:** determined by TE/CL only, for every method. Not in CNTLM (CNTLM's
  `http_has_body` ignores GET/HEAD bodies). This closes the desync where a GET body becomes the
  next request.
- **Response body:** unchanged CNTLM rules (HEAD, 1xx, 204, 304 have none). A response without
  CL/TE uses the existing "read until close" heuristic, and the connection is marked not reusable.
- **Chunk size line:** 1–16 hex digits, optional `;ext`. Data must be followed by CRLF. Any other
  input is a protocol error.
- **Header lines:**
  - A line starting with SP/HT (obs-fold) is rejected.
  - Whitespace between name and colon is rejected.
  - A line without a colon is rejected.
  - A bare CR anywhere is rejected.
  - The name must be a token.

### D4. Truncation and pool eligibility
- `dataTransfer` and `chunkedTransfer` throw `EOFException` when the peer closes before the framed
  length. Callers already turn `IOException` into "close both".
- `RequestForwarder.finishConnection` pools only when all of the following hold:
  - The response was framed by CL or chunked (not close-delimited).
  - Neither side sent `Connection: close`, by token match.
  - No exception occurred.
  - The response did not have both TE and CL.

The archived proxy-performance rule "discard or retry stale connections" still holds.

### D5. Limits live in `JntlmProperties.Limits`
`jntlm.limits` is a nested `@Data` class validated in `JntlmConfig` (fail fast, naming the
property):

| Key | Default | Applied in |
|---|---|---|
| `max-header-bytes` | 131072 | `HttpIo.recvHeaders` (running total incl. start line) |
| `max-header-count` | 256 | `HttpIo.recvHeaders` |
| `client-idle-timeout` | 300s | `Socket.setSoTimeout` on accept |
| `parent-read-timeout` | 600s | `ParentProxyManager.connect` |
| `tunnel-idle-timeout` | 0 (off) | both sockets when entering `HttpIo.tunnel` |
| `max-client-connections` | 1024 | `Semaphore` in `ProxyServer` accept loop |

- Header limits are passed in as a small immutable `HttpLimits` record, so `HttpIo` stays static
  and testable. Tests use `HttpLimits.DEFAULT`.
- 431 for client requests: the status matches the cause, and clients and tests can tell it apart
  from syntax errors. A parent violation gives 502.
- `SocketTimeoutException` while reading parent headers gives 504 if nothing has been sent to the
  client. In a body, or on the client side, the connection is closed.
- Defaults are generous on purpose: 300s idle is longer than browser keep-alive (≈60–120 s), and
  600s covers slow corporate downloads that stall between bytes. Tunnel timeout is off because
  WebSocket/SSH-over-CONNECT sessions are legitimately idle for long periods. CNTLM has none of
  these limits.
- Over-limit connections: `tryAcquire()` fails → write a static 503 with `Connection: close`
  (bounded 1 s write timeout) and close, on the accepting virtual thread. The permit is released in
  the handler's `finally`. Alternative: block on `acquire()`. Rejected, because the kernel backlog
  would hide overload and clients would time out with no reason given.

### D6. NTLM robustness (`NtlmMessages`)
- **Type-2:**
  - Require `len >= 32`, the `NTLMSSP\0` signature, and type == 2. Otherwise throw
    `NtlmException` (unchecked, new).
  - Read target info only if `len >= 48` and `offset + length <= len`. Otherwise treat it as
    empty, matching what CNTLM effectively sends for short challenges.
- **Type-3:**
  - Compute the exact size (`64 + domain + user + host + lm + nt` bytes) and allocate it.
  - Any field over 65535 bytes → `NtlmException`.
  - Output must be byte-identical to today's for inputs that fit in 1024 bytes. The existing tests
    plus a new golden-vector test with fixed client challenge/timestamp guard this.
- **Error handling:** `ProxyAuthenticator` catches `NtlmException`, closes the parent and returns
  "auth failed". `RequestForwarder` then answers 502 (today it silently closes).
- **Safety net:**
  - `ClientConnectionHandler` catches `RuntimeException`: WARN with class and message only, never
    headers, then close the client.
  - `RequestForwarder` uses try/finally so that any throwable discards the parent endpoint instead
    of pooling it.

### D7. Exposure warning
`ProxyServer.start()` (after bind) checks `boundAddress.isLoopbackAddress()`. If it is not loopback
(the wildcard `0.0.0.0`/`::` counts as non-loopback) and client auth is disabled, it logs one WARN.

- It warns rather than refusing: refusing would break existing container/VM deployments that bind
  `0.0.0.0` behind a firewall.
- Not in CNTLM (CNTLM's `-g` gateway mode has no warning).

### D8. CI supply chain
- Pin `actions/checkout` and `actions/setup-java` to full commit SHAs, with a version comment.
- Run `./gradlew` instead of an ambient `gradle`.
- Add `gradle/actions/wrapper-validation`.
- Add `.github/dependabot.yml` for the `gradle` and `github-actions` ecosystems, weekly.

No runtime effect.

## Risks / Trade-offs

- [A real client or parent sends a technically invalid but previously tolerated message (e.g.
  `Header : value`, duplicate unequal CL)] → It now fails with 400/502 instead of working. These are
  exactly the inputs that enable smuggling, so this is accepted. The error page and DEBUG log name
  the rule that failed, to make field diagnosis quick.
- [Request bodies on GET/HEAD are now forwarded] → Matches RFC 9112. A parent that ignores them
  still frames correctly because the body is CL/TE-delimited. Covered by an integration test.
- [Timeouts cut legitimate slow transfers] → Defaults are generous, `0` disables each timeout, and
  the README documents them.
- [503 on overload surprises users with very many concurrent connections] → The default of 1024 is
  far above typical desktop usage (browsers open about 6 per host), and it is configurable.
- [The ordered-list `HttpHeaders` changes `modify` semantics] → The new semantics are what the
  existing Javadoc and CNTLM say. `HttpHeadersTest` is extended to pin them.
- [Type-3 rewrite regresses authentication] → A golden byte-vector test for NTLMv2/NTLM2SR/NT
  modes with fixed nonce/timestamp, and existing integration tests.
- [Pinning actions to SHAs adds maintenance] → Dependabot updates them.

## Migration Plan

- There is no data migration. New `jntlm.limits.*` keys have defaults, and existing config files
  keep working.
- Users who hit a new 431/400/503/504 can raise or disable the relevant limit.
- Rollback: redeploy the previous `jntlm.jar`. The new keys are ignored by older versions only if
  removed. Spring Boot does not fail on unknown `jntlm.limits` keys, because
  `@ConfigurationProperties` ignores unknown fields by default, so no config rollback is needed.
- Bump `jntlm.version` minor (e.g. `1.4.0`) because the defaults change behavior.

## Open Questions

- None blocking. If field reports show a common parent proxy that sends TE+CL responses, we may
  pool them after stripping CL (currently not pooled, which is conservative).
