# Proposal

## Why

The NTLM negotiate flags sent in the Type-1 message are hardcoded per dialect (e.g. `0xa208b205` for
NTLMv2). Many corporate parent proxies (e.g. BlueCoat) reject those defaults, so users have to
discover a working value by trial and error and pin it in `jntlm.flags`. jntlm should find a working
set of flags itself, by probing the parent proxy, and remember it.

## What Changes

- Add automatic discovery of NTLM negotiate flags for the configured `jntlm.auth` dialect. jntlm
  probes the parent proxy with a sequence of candidate flag sets. A candidate is accepted only when
  the full handshake succeeds (Type-1 → Type-2 challenge → Type-3 → non-407 reply).
- Candidate order: the explicit `jntlm.flags` value (if set), then the dialect's hardcoded default,
  then progressively reduced variants of it, plus variants derived from the flags the parent
  advertises in its Type-2 challenge.
- Cache the discovered flags for all later parent connections. Invalidate the cache when the active
  parent proxy changes, or when a fresh handshake with the cached flags is rejected (with a
  cool-down so detection cannot loop).
- Detection trigger:
  - **Eager**: if `jntlm.detect.probe-url` is configured, detection runs in the background at
    startup against that URL.
  - **Lazy**: otherwise, detection runs before the first client request is forwarded. It uses a
    body-less probe derived from that request (`CONNECT` stays `CONNECT`, other methods become
    `GET`).
  - Concurrent requests wait for a single running detection instead of starting their own.
- Fallback: if no candidate succeeds, jntlm uses the dialect's hardcoded default. This is the
  current behavior when `jntlm.flags` is unset.
- New configuration: `jntlm.detect.enabled` (default `true`) and `jntlm.detect.probe-url` (default
  blank). With `enabled: false`, behavior is exactly as today: explicit `jntlm.flags` or the
  hardcoded default, with no probing.
- Log the detected flags at INFO so users can pin them in `jntlm.flags`.
- Not breaking. Existing configurations keep working, and an explicit `jntlm.flags` is still tried
  first.

## Capabilities

### New Capabilities

- `ntlm-flags-detection`: Discovers, selects, caches and invalidates the NTLM negotiate flags jntlm
  uses toward the parent proxy, including fallback to the explicit or hardcoded flags.

### Modified Capabilities

<!-- None: no main specs exist yet under openspec/specs/. -->

## Impact

- **Code**: `ntlm/NtlmMessages` exposes the per-dialect default flags and parses the Type-2 flags.
  A new flags resolver/detector component goes in `proxy/`. `RequestForwarder` gets resolved flags
  for fresh connections and reports auth rejections. `ParentProxyManager` exposes the active
  parent. `config/JntlmProperties` gets a `detect` section. `JntlmConfig` keeps parsing
  `jntlm.flags`.
- **Config/docs**: `application.yml`, `application-local.yml` comments, `README.md`, `AGENTS.md`
  gotcha about flags.
- **Network behavior**: The first request (or startup, when a probe URL is set) may open up to N
  extra short-lived connections to the parent proxy. N is bounded by the candidate list size.
- **Tests**: `NtlmMessagesTest`, a new detector unit test, and `ProxyForwardingIntegrationTest`'s
  `MockParentProxy` extended to reject specific flags.

## Assumptions

- Detection only varies negotiate flags. The `jntlm.auth` dialect stays as configured.
- Probing a body-less `GET` of the client's first request URL has no harmful side effects.
- A non-407 reply to the Type-3 message (including 4xx/5xx from the origin) means authentication
  succeeded.

## Out of Scope

- Auto-detecting the NTLM dialect (CNTLM `-M`-style magic detection).
- Persisting detected flags across restarts.
- Separate flag caches for each parent proxy. There is one cache for the currently active parent.
- Kerberos/SPNEGO (`Negotiate`) authentication.
