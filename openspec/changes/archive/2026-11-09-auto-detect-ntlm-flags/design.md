# Design

## Context

- `NtlmMessages.type1Request` picks flags through a private `getFlags(creds)`. It uses
  `creds.flags` when non-zero, otherwise a hardcoded per-dialect constant (`NTLMV2_FLAGS =
  0xa208b205`, `NTLM2SR_FLAGS = 0xa208b207`, `NT_FLAGS = 0xb205`, `LM_FLAGS = 0xb206`,
  `NTLM_FLAGS = 0xb207`). `JntlmConfig` puts the parsed `jntlm.flags` into the global
  `Credentials`.
- `RequestForwarder.forward` copies `globalCredentials` for each fresh parent connection. Pooled
  connections keep their own `Credentials`. `ProxyAuthenticator.authenticate` runs the handshake
  inline on the client's real request.
- `ParentProxyManager` holds one shared "current" parent. On failover it flushes `ConnectionPool`.
- The Type-2 challenge carries the server's negotiate flags at bytes 20..24. `type3Response`
  already echoes them.
- Motivation: see proposal.md (Why). Required behavior: see `specs/ntlm-flags-detection/spec.md`.

## Goals / Non-Goals

**Goals:**

- Put flag resolution in one component. `NtlmMessages` stays pure crypto and wire format.
- Keep the CNTLM-ported control flow of `RequestForwarder`/`ProxyAuthenticator` intact. The only
  additions are a flags lookup on fresh connections and a rejection report.
- Make detection deterministic and testable: pure candidate generation, an injectable `Clock`, and
  short timeouts.

**Non-Goals:**

- Dialect detection. Separate caches for each parent. Persisting results. Reusing probe connections
  for client traffic.

## Decisions

### D1. Components

- **`ntlm/NtlmFlags`** (new, pure, `final` utility class):
  - Holds the flag constants, moved from `NtlmMessages`.
  - `long defaultFor(Credentials)`: the per-dialect default. It ignores `creds.flags` and is the
    current `getFlags` minus the override branch.
  - `List<Long> candidates(Credentials, long explicitFlags)`: the ordered candidates (see D2).
  - `long fromChallenge(byte[] type2)`: reads the little-endian u32 at offset 20.
  - `long refine(long candidate, long serverFlags, Credentials)`: the challenge-derived candidate,
    or `0` when it is not usable.
  - `String hex(long)`: formats as `0x%08x`.
- **`NtlmMessages`**: `getFlags` becomes `creds.getFlags() != 0 ? creds.getFlags() :
  NtlmFlags.defaultFor(creds)`. Behavior does not change.
- **`proxy/NtlmFlagsResolver`** (new `@Component`): owns the cache, single-flight, probing,
  invalidation, and eager start. Dependencies: `ParentProxyManager`, `Credentials
  globalCredentials`, `JntlmProperties`, and `Clock` (defaults to `Clock.systemUTC()`; tests use a
  package-private constructor).
- **Alternative considered**: putting detection inside `ProxyAuthenticator`. Rejected because it
  would mix retry loops into the CNTLM port and probe with the client's real request, which may
  have a body.

### D2. Candidate generation (in `NtlmFlags.candidates`)

Let `D = defaultFor(creds)`. The list is built in this order, deduplicated with a
`LinkedHashSet`, and skips `0`:

1. `explicitFlags` (only if non-zero)
2. `D`
3. `v1 = D & ~(NEGOTIATE_56 | NEGOTIATE_128 | NEGOTIATE_VERSION)`: drops the high bits
4. `v2 = v1 & ~(OEM_DOMAIN_SUPPLIED | OEM_WORKSTATION_SUPPLIED)`: the known BlueCoat value
   `0x00088205` for NTLMv2
5. `v3 = v2 & ~ALWAYS_SIGN`
6. `v4 = v3 & ~NEGOTIATE_EXTENDED_SESSION_SECURITY`: minimal `NTLM | REQUEST_TARGET | charset`

Resulting lists for each dialect:

- NTLMv2: `a208b205, 0008b205, 00088205, 00080205, 00000205`
- NT: `b205, 8205, 0205`

The list is bounded at 6 entries plus at most 2 challenge-derived insertions, `MAX_PROBES = 8`.

**Refine rule** (`refine`): `r = candidate & serverFlags`. It is usable only if all of these hold:

- `r != 0`
- `r` keeps `NTLM (0x200)`
- `r` keeps every charset bit (`UNICODE`/`NEGOTIATE_OEM`) that the candidate had
- `r` has not been tried yet

A usable `r` is moved (or inserted) directly after the current candidate, so it is the next one
probed even if it was already queued later in the list.

**Rationale**: removing optional bits step by step covers the failures seen in practice, and the
refine rule uses the parent's own answer.

**Alternative considered**: brute-forcing flag subsets. Rejected because it is unbounded and slow.

### D3. Probe procedure (`NtlmFlagsResolver.probe(candidate, template)`)

For each candidate:

1. Open a fresh `Endpoint` via `parentProxyManager.connect()` and set `SO_TIMEOUT =
   PROBE_TIMEOUT_MS (10 s)`.
2. Build `creds = globalCredentials.copy().setFlags(candidate)`. Send `template` with
   `Proxy-Authorization: NTLM <type1>`, `Proxy-Connection: keep-alive`, `Content-Length: 0`, and no
   `Transfer-Encoding`.
3. Read the reply with `HttpIo.recvHeaders`:
   - Non-407: **accept**. The parent does not require auth.
   - 407: drop the body. Decode the challenge with a shared helper extracted from
     `ProxyAuthenticator.decodeChallenge` (made package-private static). If the challenge is
     missing or ≤ 40 bytes, **reject** with reason "no challenge".
4. Build the Type-3 and send `template` again with the Type-3 header. If the peer closed the
   connection after the challenge, **reject** with reason "connection closed". NTLM is bound to the
   connection, so reconnecting would be pointless.
5. Read the reply. 407 means **reject**, and the resolver computes `refine(candidate,
   fromChallenge(challenge))`. Any other code means **accept**.
6. Always close the probe endpoint. Probe connections are never pooled.

IOException or timeout means **reject**. Each rejection is logged at DEBUG with the hex flags and
the reason.

**Templates**:

- Lazy: built from the client request with `request.copy()`:
  - `CONNECT` stays as it is.
  - Other methods: set method to `GET`, remove `Proxy-Authorization`, and remove body headers.
- Eager: built from `jntlm.detect.probe-url` with `java.net.URI`:
  - `http`: `GET <url> HTTP/1.1` with `Host`.
  - `https`: `CONNECT host:port HTTP/1.1` (port defaults to 443) with `Host`.

Templates are built as `HttpMessage`, using the existing `HttpMessage`/`HttpHeaders` API.

### D4. Cache, single-flight and API

State: `AtomicReference<CompletableFuture<Resolved>> current`, where `record Resolved(long flags,
ParentProxy parent, boolean detected, Instant at)`.

`long flagsFor(HttpMessage request)` is called by `RequestForwarder` for fresh connections:

- If detection is disabled, return `explicit != 0 ? explicit : NtlmFlags.defaultFor(global)`.
- If `current` holds a completed `Resolved` whose `parent` equals
  `parentProxyManager.activeParent()`, return its flags.
- Otherwise CAS a new future into `current`:
  - The winner runs detection on the calling (virtual) thread and completes the future.
  - Losers `join()` the existing future.
- If detection finds nothing, complete with `Resolved(defaultFor, parent, false, now)` and log a
  WARN (fallback).
- On success, log at INFO: `Detected NTLM flags 0x%08x for parent {}; set jntlm.flags to pin
  them`.

`void reportRejected(long flags)`: if the cached `Resolved.flags == flags` and `now - at >=
COOLDOWN (60 s)`, CAS `current` back to `null`. Otherwise do nothing.

Eager start: `@EventListener(ApplicationReadyEvent.class)` starts a virtual thread running
`detect(probeTemplate)` through the same single-flight path, but only when `probe-url` is set and
detection is enabled.

**Alternative considered**: a `synchronized` method. Rejected because it pins virtual threads and
gives no reuse of the in-flight result.

### D5. `ParentProxyManager.activeParent()`

Add `public ParentProxy activeParent() { return parents.get(current.get()); }`. The resolver
compares parents on every lookup, so a failover invalidates the cache implicitly. `ParentProxy` is a
record, so `equals` works. This needs no callback and creates no circular bean dependency.

### D6. `RequestForwarder` integration (minimal)

- Fresh-connection branch: `creds = globalCredentials.copy();
  creds.setFlags(flagsResolver.flagsFor(request));`.
  - `request` here can be `null` only on the `continue beginning` retry path, and that path always
    sets `request`. If it is `null`, fall back to `globalCredentials`' flags.
  - Detection happens before `parentProxyManager.connect()` for the client's own connection, so
    that connection reflects any parent switch.
- In loop 1, `data1.getCode() == 407 && !wasCached && !noauth` means a fresh handshake failed. Call
  `flagsResolver.reportRejected(creds.getFlags())` before the existing 407 relay.
- `ProxyAuthenticator` is unchanged apart from extracting `decodeChallenge`.

### D7. Configuration

`JntlmProperties.Detect detect` with:

- `boolean enabled = true`
- `String probeUrl = ""`

These bind to `jntlm.detect.enabled` and `jntlm.detect.probe-url`. `jntlm.flags` keeps its meaning,
and its parsed value stays in `globalCredentials.flags`, which is the explicit candidate. Comments
in `application.yml` are updated.

## Risks / Trade-offs

- [Each probe adds connections and requests at first use or failover, up to 8 round trips] →
  Bounded list, a 10 s per-probe timeout, the known-good value early in the list, and the logged
  value can be pinned via `jntlm.flags`.
- [A lazy probe sends a `GET` to the client's URL, which is an extra origin hit] → Only once per
  detection. Users who mind can set `probe-url`.
- [Some proxies count failed handshakes toward account lockout] → Failures with the right password
  but wrong flags normally fail before the Type-3. The list is short, and `detect.enabled: false`
  is available. This is documented in the README.
- [A wrong password makes every candidate fail at Type-3] → This falls back to the default, and the
  cool-down prevents repeated detection storms. The existing 407→Basic-realm behavior tells the
  user.
- [All first requests wait while detection runs] → Detection is bounded by
  `MAX_PROBES × PROBE_TIMEOUT_MS`. Eager detection removes the wait.
- [The CONNECT probe opens a tunnel to the origin] → It is closed immediately after headers.

## Migration Plan

No migration is needed. Defaults enable detection. Existing `jntlm.flags` values are tried first and
still work. To roll back, set `jntlm.detect.enabled: false`.
