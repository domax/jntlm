# Tasks

## 1. Ordered, token-aware headers

- [x] 1.1 Rewrite `http/HttpHeaders` as an ordered `ArrayList` of `(name, value)` entries (design D2): `add` appends; `modify` replaces the first match in place and removes later matches; `remove` removes all matches; `get` returns the first; `getAll` returns all in order; `copy()` deep-copies. Keep the public method names used by callers. Verify `./gradlew compileJava` succeeds.
- [x] 1.2 Change `containsToken(name, token)` to split every matching value on `,`, trim, and compare case-insensitively; Javadoc "Not in CNTLM: hlist_subcmp is a substring match". Update `HttpMessage.copy()` to use `headers.copy()`. Verify with 1.3.
- [x] 1.3 Extend `HttpHeadersTest`: repeated identical `Set-Cookie` lines both preserved; interleaved `A: 1`, `B: 2`, `A: 3` serialized in that order; `modify` keeps first position and drops later duplicates; `containsToken("Connection","close")` true for `keep-alive, Close` and false for `notclose`. Verify `./gradlew test --tests '*HttpHeadersTest' --tests '*HttpMessageTest'` passes.

## 2. Strict framing in HttpIo

- [x] 2.1 Add `http/HttpProtocolException extends IOException` with an `int status` (400, 431, 502) and reason (design D1), and `http/HttpLimits` record (`maxHeaderBytes`, `maxHeaderCount`; `DEFAULT` = 131072/256). Verify `./gradlew compileJava`.
- [x] 2.2 In `HttpIo.recvHeaders` (pass `HttpLimits`; keep an overload using `DEFAULT` for tests): reject obs-fold, whitespace before colon, missing colon, non-token names, bare CR, malformed request/status line, and over-limit count/bytes (431 for requests, 502 for responses), via `HttpProtocolException` (design D3/D5). Clean EOF before the first byte keeps today's "no message" result. Verify with 2.6.
- [x] 2.3 Add Content-Length parsing (`^[0-9]{1,18}$`, identical duplicates or comma lists collapsed to one field via `modify`, otherwise 400 request / 502 response) and Transfer-Encoding final-token check; reject requests with TE+CL or a non-`chunked` final coding with 400; for responses with TE+CL remove CL and flag the message non-reusable (design D3). Verify with 2.6.
- [x] 2.4 Make request body detection depend only on TE/CL for every method (Javadoc "Not in CNTLM: http_has_body ignores GET/HEAD bodies"); keep response rules (HEAD/1xx/204/304 no body; no CL/TE → read-until-close and flag non-reusable). Verify with 2.6.
- [x] 2.5 Make `chunkedTransfer` accept only 1–16 hex digits with optional `;ext`, require CRLF after each chunk's data, and make `dataTransfer`/`chunkedTransfer` throw `EOFException` on premature EOF instead of returning silently (design D4). Verify with 2.6.
- [x] 2.6 Add `src/test/java/net/domax/jntlm/http/HttpIoFramingTest` using byte-array streams covering every scenario in `specs/http-message-framing` at the parser level plus header limits (257 lines, 2000 bytes with limit 1024) and truncated fixed/chunked bodies. Verify `./gradlew test --tests '*HttpIoFramingTest'` passes.

## 3. Error responses and pool eligibility in the forwarder

- [x] 3.1 In `server/ClientConnectionHandler`, catch `HttpProtocolException` from reading a client request and, if nothing was written yet, send an `ErrorPages` reply with its status (400/431) and `Connection: close`, then close. Catch `RuntimeException`, log WARN with exception class and message only, and close (design D6). Verify with 3.4.
- [x] 3.2 In `proxy/RequestForwarder`: map `HttpProtocolException` on parent response headers to 502, and `SocketTimeoutException` on parent headers to 504, only if no response bytes were sent to the client; otherwise close. Wrap each exchange in try/finally so any throwable discards (closes) the parent endpoint and never pools it. Keep the labeled two-pass loop structure. Verify with 3.4.
- [x] 3.3 In `RequestForwarder.finishConnection`, pool only when the response was CL- or chunk-framed, not flagged non-reusable, no `Connection: close` token on either side, and no exception occurred (design D4). Verify with 3.4.
- [x] 3.4 Add `src/test/java/net/domax/jntlm/proxy/HttpFramingIntegrationTest` (MockParentProxy pattern, extending the mock to send raw scripted responses where needed) covering end-to-end: 400 for malformed/ambiguous requests with `parent.connectionsAccepted() == 0`; 502 for malformed parent headers and invalid parent CL; TE+CL response relayed chunked without CL and parent connection not reused; GET with body forwarded; parent closing mid-body closes the client and the next request opens a new parent connection; unframed response not pooled; framed keep-alive response pooled. Verify `./gradlew test --tests '*HttpFramingIntegrationTest' --tests '*ProxyForwardingIntegrationTest' --tests '*ClientAuthIntegrationTest'` passes.

## 4. Resource limits and timeouts

- [x] 4.1 In `config/JntlmProperties`, add `private Limits limits = new Limits();` with nested `@Data public static class Limits` (`maxHeaderBytes = 131072`, `maxHeaderCount = 256`, `Duration clientIdleTimeout = 300s`, `Duration parentReadTimeout = 600s`, `Duration tunnelIdleTimeout = ZERO`, `int maxClientConnections = 1024`) with Javadoc. In `JntlmConfig`, validate (negative values, zero header limits → `IllegalStateException` naming the property) and expose an `HttpLimits` bean. Verify with 4.5.
- [x] 4.2 Pass `HttpLimits` into `ClientConnectionHandler`/`RequestForwarder` header reads; set `SO_TIMEOUT` = `clientIdleTimeout` on accepted client sockets and `parentReadTimeout` in `ParentProxyManager.connect`; on entering `HttpIo.tunnel`, set both sockets' `SO_TIMEOUT` to `tunnelIdleTimeout`, and close both on `SocketTimeoutException`. Verify with 4.5.
- [x] 4.3 In `server/ProxyServer`, add a fair `Semaphore` when `maxClientConnections > 0`; on accept `tryAcquire()`, otherwise write `ErrorPages` 503 with `Connection: close` (1 s write timeout) and close without dispatching; release the permit in the handler's `finally`. Verify with 4.5.
- [x] 4.4 Add commented `limits:` block with defaults to `src/main/resources/application.yml`. Verify the app context loads (`./gradlew test`).
- [x] 4.5 Add `src/test/java/net/domax/jntlm/proxy/ResourceLimitsIntegrationTest` covering each scenario in `specs/resource-limits`: 431 for 257 headers and for oversized section (also with client auth enabled, before credential check), 502 for 300-line parent response, client idle close at 1 s, idle not closed when 0, 504 on silent parent, mid-body parent stall closes client, idle tunnel survives client-idle-timeout by default, tunnel closed with tunnel-idle-timeout 1 s, 503 on third connection with limit 2 and no parent connection opened, permit released after close; plus `JntlmConfig` validation tests (negative timeout names `jntlm.limits.client-idle-timeout`). Verify `./gradlew test --tests '*ResourceLimitsIntegrationTest'` passes.

## 5. NTLM robustness

- [x] 5.1 Add unchecked `ntlm/NtlmException`. In `NtlmMessages`, validate Type-2 (`len >= 32`, `NTLMSSP\0`, type 2) and read target info only when `len >= 48` and `offset + length <= len` (design D6). Verify with 5.4.
- [x] 5.2 Replace the fixed `NTLM_BUFSIZE` Type-3 buffer with an exactly sized allocation; throw `NtlmException` if any field exceeds 65535 bytes. Before changing it, add a golden-vector test capturing current Type-3 bytes for NTLMv2, NTLM2SR and NT modes with fixed client nonce/timestamp; it must stay byte-identical afterwards. Verify with 5.4.
- [x] 5.3 In `proxy/ProxyAuthenticator`, catch `NtlmException`, close the parent connection and report authentication failure; make `RequestForwarder` answer `502 Bad Gateway` for failed parent authentication when nothing was sent to the client. Verify with 5.4.
- [x] 5.4 Extend `NtlmMessagesTest` (44-byte challenge, wrong signature, out-of-range target-info offset, 2000-byte target info, golden vectors) and add an integration case where `MockParentProxy` sends `Proxy-Authenticate: NTLM AAAA` → client gets 502, parent connection closed. Verify `./gradlew test --tests '*NtlmMessagesTest' --tests '*HttpFramingIntegrationTest'` passes.

## 6. Exposure warning

- [x] 6.1 In `server/ProxyServer.start()`, after binding, log one WARN naming the bound address and suggesting `jntlm.client-auth.enabled` or `127.0.0.1` when the address is not loopback (wildcard counts) and client auth is disabled (design D7). Verify with 6.2.
- [x] 6.2 Add a test with a Logback `ListAppender` covering the three `client-authentication` exposure scenarios (wildcard + disabled → WARN, loopback → none, wildcard + enabled → none). Verify `./gradlew test --tests '*ProxyServer*'` passes.

## 7. CI supply chain

- [x] 7.1 In `.github/workflows/gradle-publish.yml`, pin `actions/checkout` and `actions/setup-java` to full commit SHAs with `# vX` comments, add a `gradle/actions/wrapper-validation` step (SHA-pinned), and replace `gradle` invocations with `./gradlew` (design D8). Verify the YAML parses (`python3 -c 'import yaml,sys;yaml.safe_load(open(sys.argv[1]))' .github/workflows/gradle-publish.yml`).
- [x] 7.2 Add `.github/dependabot.yml` with weekly `gradle` and `github-actions` ecosystems. Verify the YAML parses.

## 8. Documentation

- [x] 8.1 Update `README.md`: add `jntlm.limits.*` rows to the Configuration table with defaults; add a short "Hardening" note listing the new 400/431/502/503/504 behaviors, the exposure warning, and how to disable each timeout. Verify table columns align and defaults match `application.yml`.
- [x] 8.2 Update `AGENTS.md`: mention strict framing (`HttpProtocolException`, pool-only-when-cleanly-framed rule), `jntlm.limits`, and the "Not in CNTLM" deviations in Gotchas. Bump `jntlm.version` in `application.yml` to `1.4.0`. Verify `./gradlew build` reports the new version.

## 9. Integration checks

- [x] 9.1 Run `./gradlew spotlessApply build` and verify it succeeds with all tests green and no Spotless violations.
- [x] 9.2 Run `./gradlew test --tests '*ProxyPerformanceBenchmarkTest'` and verify no workload regresses by more than ~10% versus the pre-change baseline on the same machine.
- [x] 9.3 Manual smoke (local profile): verify `curl -x http://127.0.0.1:3128 https://example.com -I` and a plain-HTTP GET succeed through the real parent, and `printf 'GET http://example.com/ HTTP/1.1\r\nHost : x\r\n\r\n' | nc 127.0.0.1 3128` returns 400.

## Workflow follow-up

- Implement this change before `optimize-pool-and-tunnel`; both touch `HttpIo`.
- Archive with `/opsx-archive` after review, syncing `http-message-framing`, `resource-limits`, `ntlm-authentication` and the `client-authentication` delta.
