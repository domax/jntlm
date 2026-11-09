# Tasks

## 1. NTLM flag primitives (`ntlm/`)

- [x] 1.1 Create `ntlm/NtlmFlags` (final utility class with the MIT header). Move the flag
  constants out of `NtlmMessages` and add `defaultFor(Credentials)`, `fromChallenge(byte[])` (LE
  u32 at offset 20) and `hex(long)` (`0x%08x`). Change `NtlmMessages.getFlags` to
  `creds.getFlags() != 0 ? creds.getFlags() : NtlmFlags.defaultFor(creds)`. Verify that the
  existing `NtlmMessagesTest` passes unchanged with `./gradlew test --tests '*NtlmMessagesTest'`.
- [x] 1.2 Add `NtlmFlags.candidates(Credentials, long explicitFlags)` following design D2 (explicit
  value, default, v1..v4, deduplicated, no zeros). Add `NtlmFlagsTest` and verify these cases:
  - NTLMv2 with no explicit value gives `[0xa208b205, 0x0008b205, 0x00088205, 0x00080205, 0x00000205]`.
  - The explicit value `0x00088205` is first and not repeated later.
  - NT gives `[0xb205, 0x8205, 0x0205]`.
- [x] 1.3 Add `NtlmFlags.refine(long candidate, long serverFlags, Credentials)` following the D2
  refine rule (returns `0` when not usable). In `NtlmFlagsTest`, verify that `refine(0xa208b205,
  0x00088205)` returns `0x00088205`, and that a result without `NTLM` or without the charset bit
  returns `0`.

## 2. Supporting changes in config and proxy

- [x] 2.1 Add a nested `Detect` class to `JntlmProperties` with `enabled = true` and `probeUrl = ""`,
  bound to `jntlm.detect.enabled` and `jntlm.detect.probe-url`, with Javadoc on each field. Add an
  annotated `detect:` block to `application.yml`. Verify with `./gradlew build`.
- [x] 2.2 Add `ParentProxyManager.activeParent()` returning `parents.get(current.get())`. Verify with
  a test in `ParentProxyTest` or a new `ParentProxyManagerTest` that it returns the first
  configured parent.
- [x] 2.3 Extract `ProxyAuthenticator.decodeChallenge` as a package-private static method so the
  resolver can reuse it, with no change to its behavior. Verify that
  `ProxyForwardingIntegrationTest` still passes.

## 3. Flags resolver (`proxy/NtlmFlagsResolver`)

- [x] 3.1 Extend `MockParentProxy` in the test sources, extracting it to a package-private test
  class if that makes sharing easier. Make it configurable to:
  - reply 407 with no challenge for a set of rejected Type-1 flags;
  - set the Type-2 flags field;
  - reply 407 to Type-3 for chosen flags;
  - count the connections and handshakes it receives.

  Verify that the existing integration tests still pass.
- [x] 3.2 Implement the probe procedure (design D3): a fresh endpoint, a 10 s `SO_TIMEOUT`, Type-1
  → challenge → Type-3 → reply classification, probe connections always closed, and a DEBUG log
  for each rejection. Add lazy template building (CONNECT is kept; anything else becomes a
  body-less `GET`) and eager template building from `probe-url` (`http` → `GET`, `https` →
  `CONNECT host:443`). In `NtlmFlagsResolverTest`, verify against the mock parent the outcomes
  accept, no-challenge reject, Type-3 reject, and non-407 accept. Also verify the templates
  produced for `POST`, `HEAD`, `CONNECT`, `http://` and `https://`.
- [x] 3.3 Implement detection (D2 + D4): walk the candidates up to `MAX_PROBES = 8`, insert refined
  candidates after the current one, log the result at INFO, and fall back to `defaultFor` with a
  WARN. Verify the spec scenarios in `NtlmFlagsResolverTest`:
  - explicit value accepted first;
  - default accepted;
  - `0x00088205` reached when only that value is accepted;
  - challenge-derived candidate;
  - all rejected, falling back to the default;
  - explicit value rejected, falling back to the default.
- [x] 3.4 Implement the cache and single-flight `flagsFor(HttpMessage)` (D4). Return the cached
  flags while the parent is unchanged. Support the `detect.enabled=false` passthrough (explicit
  value, else default, no probes). Verify with tests:
  - a second call sends no probes (check the mock's handshake count);
  - two concurrent calls run detection once;
  - disabled mode opens 0 probe connections and returns the explicit flags.
- [x] 3.5 Implement `reportRejected(long flags)` with a 60 s cool-down, using an injected `Clock`.
  Also invalidate the cache when `activeParent()` changes. Verify with tests:
  - a rejection after the cool-down makes the next call re-detect;
  - a rejection within the cool-down keeps the cache;
  - a rejection with flags that do not match the cache is ignored;
  - a parent change triggers re-detection (two mock parents, first one stopped).
- [x] 3.6 Add eager detection: an `@EventListener(ApplicationReadyEvent.class)` that starts a
  virtual thread when `probe-url` is set and detection is enabled, sharing the single-flight
  future. Verify with a test that calls the listener method directly and checks that a later
  `flagsFor` call sends no new probes.

## 4. Forwarder integration

- [x] 4.1 Inject `NtlmFlagsResolver` into `RequestForwarder`. In the fresh-connection branch, set
  `creds.setFlags(flagsResolver.flagsFor(request))` before `parentProxyManager.connect()`. Call
  `flagsResolver.reportRejected(creds.getFlags())` when loop 1 sees a 407 on a fresh,
  authenticated connection (`!wasCached && !noauth`). Update the manual wiring in
  `ProxyForwardingIntegrationTest`. Verify with `./gradlew test`.
- [x] 4.2 Add integration tests in `ProxyForwardingIntegrationTest`. Verify:
  - with a mock parent that rejects `0xa208b205`, a client GET succeeds end to end and a second
    request on a new connection sends a Type-1 with the detected flags and no probes;
  - a client POST with a body is forwarded exactly once, with its body intact, after a lazy GET
    probe.

## 5. Documentation and finish

- [x] 5.1 Update `README.md` (configuration table: `jntlm.detect.enabled`, `jntlm.detect.probe-url`,
  and the new meaning of `jntlm.flags` as the first candidate; a short "Flag auto-detection"
  section including the lockout and extra-connection notes). Update the `AGENTS.md` gotcha about
  flags and the comments in `application-local.yml`. Verify by reading the rendered Markdown and
  checking that the documented keys match `JntlmProperties`.
- [x] 5.2 Run `./gradlew spotlessApply build`. Verify that formatting, the license headers and all
  tests pass.

## Workflow follow-up

- Manually verify with the `local` profile against the real BlueCoat parent, with `jntlm.flags`
  removed, and confirm that the INFO log reports `0x00088205` (or another working value).
- Archive the change with `/opsx-archive` after review.
