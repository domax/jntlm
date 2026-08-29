# AGENTS.md

Guidance for AI coding agents working on **jntlm** — a Java 21 / Spring Boot rewrite of the
[CNTLM](https://cntlm.sourceforge.net/) NTLM-authenticating HTTP proxy. It listens locally
(unauthenticated) and transparently performs the NTLM handshake to a corporate parent proxy.

## Big picture

Request flow: **client → `ProxyServer` → `ClientConnectionHandler` → `RequestForwarder` → parent
proxy**.

- `server/` — `ProxyServer` is a Spring `SmartLifecycle` bean that binds a `ServerSocket` and runs
  an accept loop; each client is handled on a **virtual thread** (`clientExecutor` in
  `JntlmConfig`).
  `ClientConnectionHandler` loops per keep-alive request and follows `ForwardResult.Type.REROUTE`.
- `proxy/` — `RequestForwarder` is the core engine (a faithful port of CNTLM's `forward_request`;
  keep the labeled two-pass `loop 0 = client→parent`, `loop 1 = parent→client` structure).
  `ProxyAuthenticator` runs the NTLM 407 handshake; `ConnectionPool` caches already-authenticated
  parent connections (NTLM auth is bound to a TCP connection, so reuse skips re-auth);
  `ParentProxyManager` does round-robin failover over `jntlm.parents`.
- `ntlm/` — pure NTLM crypto/message building (`NtlmMessages`, `NtlmHashes`, `NtlmCrypto`, `Md4`).
  All multibyte fields are **little-endian** (`Le`). `Credentials` holds dialect switches + hashes.
- `http/` — hand-rolled HTTP wire I/O (`HttpIo`, `HttpMessage`, `HttpHeaders`); no servlet stack.
- `config/` — `JntlmProperties` (`@ConfigurationProperties(prefix="jntlm")`) + `JntlmConfig`
  builds the global `Credentials` bean; `AuthMode` maps dialects to hash switches.

## Project-specific conventions

- **CNTLM parity is the prime directive.** Most classes cite the exact CNTLM C function they port
  (e.g. `forward.c`'s `forward_request`, `proxy.c`'s `proxy_authenticate`). Preserve that behavior;
  Javadoc the CNTLM source when adding logic. Don't "modernize" the control flow casually.
- **Lombok everywhere:** `val`/`var`, `@Data`, `@Slf4j`, `@RequiredArgsConstructor`, `@Getter`
  `@Accessors(fluent = true)` (note fluent accessors, e.g. `endpoint.in()`, not `getIn()`).
- **Version single source of truth:** `jntlm.version` in `src/main/resources/application.yml`.
  `build.gradle` parses it to set the Gradle `version`; do not hardcode versions elsewhere.
- Every `.java` file starts with the header `/* JNTLM © Licensed under MIT $YEAR. */` (enforced by
  Spotless).
- Not a web app: no controllers/MVC. Networking is raw `Socket`/`ServerSocket` + virtual threads.

## Developer workflows

- Build: `./gradlew build` — Java 21 toolchain, Spring Boot 4.
- Format (required before commit): `./gradlew spotlessApply` (google-java-format 1.27 + license
  header).
- Test: `./gradlew test` (JUnit 5 + Mockito, JaCoCo report at `build/reports/jacoco/test/html`). See
  `ProxyForwardingIntegrationTest` for the pattern: an in-JVM `MockParentProxy` speaking the NTLM
  407 handshake; wire real components manually (`new RequestForwarder(manager, pool, auth, creds)`).
- Run locally: activate the `local` profile — `application-local.yml` (excluded from the boot jar)
  overrides `parents`, `flags`, and log levels for a real corporate proxy.

## Gotchas

- NTLM negotiate `flags` sometimes need per-proxy overrides (some proxies reject the default
  `0xa208b205`); see the annotated `application-local.yml` example (`0x00088205` for BlueCoat).
- Credentials: supply either a plaintext `password` (hashes derived at startup in `JntlmConfig`)
  **or** pre-computed hex hashes (`pass-lm`/`pass-nt`/`pass-ntlm2`) — not both.

