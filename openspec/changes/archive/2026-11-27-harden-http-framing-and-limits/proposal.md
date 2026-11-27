# Proposal

## Why

jntlm reuses authenticated parent-proxy connections across all clients, but its HTTP parser
accepts ambiguous or malformed message framing (conflicting `Content-Length`/`Transfer-Encoding`,
invalid or negative lengths, bad chunk sizes, whitespace before the colon, bare CR). A request or
response whose body is not fully and exactly consumed can leave a pooled parent connection
desynchronized, so one client may receive bytes of another client's response. The parser also has
no total header limits and sockets have no read timeouts, and a malformed NTLM Type-2 challenge can
crash a connection handler and leak the parent socket. These are cheap to fix now and become
material whenever `listen-address` is opened beyond loopback.

## What Changes

- Strict HTTP/1.1 message framing for client requests and parent responses (RFC 9112 rules), with
  `400 Bad Request` for malformed client requests and `502 Bad Gateway` for malformed parent
  responses. Body framing is decided by `Transfer-Encoding`/`Content-Length`, not by the request
  method. **BREAKING (behavioral)**: previously tolerated malformed messages are now rejected; this
  intentionally deviates from CNTLM's lenient `headers_recv`/`http_has_body`.
- `Connection`, `Proxy-Connection` and `Transfer-Encoding` values are matched as comma-separated
  tokens instead of case-insensitive substrings (deviation from CNTLM's `hlist_subcmp`).
- A parent connection is returned to the pool only when both the request and the response were
  unambiguously framed and completely transferred.
- Headers preserve every field line, including duplicates with identical values, in received
  order (fixes value de-duplication and regrouping in the current header store).
- Configurable resource limits under a new `jntlm.limits.*` block: total header-section size,
  header-line count, client idle timeout, parent read timeout, tunnel idle timeout and maximum
  concurrent client connections (`431` for oversized client headers, `504` when the parent stops
  answering, `503` when the connection limit is exceeded).
- Malformed or oversized NTLM Type-2 challenges fail the handshake cleanly (parent connection
  closed, client receives `502`), and any unexpected internal error closes both connections without
  pooling.
- A startup WARN when the listener is bound to a non-loopback address while client authentication
  is disabled (open relay using the configured corporate identity).
- CI supply-chain hygiene: pin third-party actions to commit SHAs, build with the Gradle wrapper,
  validate the wrapper, and add Dependabot for Gradle and GitHub Actions.

## Capabilities

### New Capabilities

- `http-message-framing`: How client requests and parent responses are parsed, validated, framed
  and relayed, and when a parent connection is safe to reuse after an exchange.
- `resource-limits`: Bounds on header size, concurrent client connections and socket idle/read
  time, with their defaults and error responses.
- `ntlm-authentication`: Robust handling of the parent's NTLM Type-2 challenge and of internal
  failures during the handshake.

### Modified Capabilities

- `client-authentication`: adds a startup warning when the listener is exposed beyond loopback with
  client authentication disabled.

## Impact

- Code: `http/HttpIo`, `http/HttpHeaders`, `http/HttpMessage`, `proxy/RequestForwarder`,
  `proxy/ProxyAuthenticator`, `proxy/ParentProxyManager`, `proxy/ErrorPages`, `ntlm/NtlmMessages`,
  `server/ProxyServer`, `server/ClientConnectionHandler`, `config/JntlmProperties`,
  `config/JntlmConfig`.
- Configuration: new optional `jntlm.limits.*` keys with backward-compatible defaults;
  `application.yml`, `README.md`, `AGENTS.md` updated.
- CI: `.github/workflows/gradle-publish.yml`, new `.github/dependabot.yml`.
- Tests: new framing, limits and NTLM-robustness tests; existing integration tests must stay green.
- No new runtime dependencies.

## Assumptions

- Deployment exposure (loopback-only vs. shared) is unknown, so hardening is always on; defaults are
  chosen so that well-formed traffic from mainstream clients and proxies is unaffected.
- The non-loopback exposure check warns rather than refusing to start, to avoid breaking existing
  deployments.
- Responses without `Content-Length`/`Transfer-Encoding` keep CNTLM's body heuristic for
  compatibility, but their parent connection is no longer pooled.

## Out of Scope

- Salted/slow password hashing for client BASIC auth (`{sha256}` remains; a follow-up change can add
  PBKDF2).
- Connection-pool idle eviction, pool size caps, tunnel throughput and header-parsing speed (covered
  by the separate `optimize-pool-and-tunnel` change).
- Half-close semantics for CONNECT tunnels, `Expect: 100-continue` handling, HTTP/2.
- The CNTLM-inherited NT-response placement in Type-3 messages for non-NTLMv2 dialects.
