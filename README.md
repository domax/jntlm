# JNTLM — Java NTLM-authenticating HTTP proxy

[![Made with Java](https://img.shields.io/badge/Java-21-blue?logo=openjdk&logoColor=white)](https://openjdk.org "OpenJDK homepage")
[![Made with Spring Boot](https://img.shields.io/badge/SpringBoot-4-blue?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot "Spring Boot homepage")
[![GitHub License](https://img.shields.io/github/license/domax/jntlm)](https://opensource.org/licenses/MIT "MIT License page")
[![CodeQL](https://github.com/domax/jntlm/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/domax/jntlm/actions/workflows/github-code-scanning/codeql)
[![Gradle Package](https://github.com/domax/jntlm/actions/workflows/gradle-publish.yml/badge.svg)](https://github.com/domax/jntlm/actions/workflows/gradle-publish.yml)

[![Buy me a coffee](https://img.buymeacoffee.com/button-api/?text=Buy+me+a+coffee&emoji=&slug=domax&button_colour=F9A154&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=FFFFFF)](https://www.buymeacoffee.com/domax)

---

A Java 21 / Spring Boot rewrite of the [CNTLM](https://cntlm.sourceforge.net/)
NTLM-authenticating HTTP proxy. It listens locally (unauthenticated by default, with optional BASIC
client authentication) and transparently performs the NTLM handshake to a corporate parent proxy, so
tools that cannot speak NTLM themselves can reach the internet through the local port.

This implementation was designed to be as lightweight as possible, with no servlet stack or Spring
MVC. It uses raw `Socket`/`ServerSocket` networking and virtual threads for concurrency. It is a
faithful port of CNTLM's core logic, with a focus on maintainability and modern Java practices.

         _ _   _ _____ _     __  __
        | | \ | |_   _| |   |  \/  |
     _  | |  \| | | | | |   | |\/| |
    | |_| | |\  | | | | |___| |  | |
     \___/|_| \_| |_| |_____|_|  |_|

## Disclaimer

This project is not affiliated with or endorsed by the original CNTLM project or its authors. It is
an independent implementation that aims to provide similar functionality with modern Java practices.

Also, this project is not a legal advice or a security solution. It is provided "as is" without any
warranties or guarantees. Use it at your own risk.

Please review the code and documentation carefully before using it in production environments. For
any legal or security concerns, consult with a qualified professional.

This project is intended for educational and informational purposes only.

By using this project, you agree to the terms of the [MIT License](LICENSE.txt) and then merge it
into the site-policy repo. This is to ensure that I can review and iterate on the changes before
they are made public. I appreciate your understanding and cooperation in this process.

## Big picture

Request flow: **client → `ProxyServer` → `ClientConnectionHandler` → `RequestForwarder` → parent
proxy**.

* `server/`:
  - `ProxyServer` is a Spring `SmartLifecycle` bean that binds a `ServerSocket` and runs an accept
    loop; each client is handled on a **virtual thread** (`clientExecutor` in
    `JntlmConfig`).
  - `ClientConnectionHandler` loops per keep-alive request and follows
    `ForwardResult.Type.REROUTE`. When enabled, it gates the first request of each connection
    through `ClientAuthenticator` (optional BASIC client auth; not in CNTLM).
* `proxy/`:
  - `RequestForwarder` is the core engine (a faithful port of CNTLM's `forward_request`; keep the
    labeled two-pass `loop 0 = client→parent`, `loop 1 = parent→client` structure).
  - `ProxyAuthenticator` runs the NTLM 407 handshake;
  - `ConnectionPool` caches already-authenticated parent connections (NTLM auth is bound to a TCP
    connection, so reuse skips re-auth), bounded by `jntlm.pool.*` with idle eviction;
  - `ParentProxyManager` does round-robin failover over `jntlm.parents`;
  - `NtlmFlagsResolver` detects and caches working NTLM negotiate flags for the active parent.
* `ntlm/` — pure NTLM crypto/message building (`NtlmMessages`, `NtlmFlags`, `NtlmHashes`,
  `NtlmCrypto`, `Md4`).
  All multibyte fields are **little-endian** (`Le`). `Credentials` holds dialect switches + hashes.
* `http/` — hand-rolled HTTP wire I/O (`HttpIo`, `HttpMessage`, `HttpHeaders`); no servlet stack.
* `config/`:
  - `JntlmProperties` (`@ConfigurationProperties(prefix="jntlm")`) + `JntlmConfig`
    builds the global `Credentials` bean;
  - `AuthMode` maps dialects to hash switches.

## Developer workflows

- **Build:** `./gradlew build` — Java 21 toolchain, Spring Boot 4.
- **Format (required before commit):** `./gradlew spotlessApply` (google-java-format 1.27 + license
  header).
- **Test:** `./gradlew test` (JUnit 5 + Mockito, JaCoCo report at
  `build/reports/jacoco/test/html`). See `ProxyForwardingIntegrationTest` for the pattern: an in-JVM
  `MockParentProxy` speaking the NTLM 407 handshake; wire real components manually
  (`new RequestForwarder(manager, pool, auth, creds)`).
- **Performance smoke benchmark:** `./gradlew test --tests '*ProxyPerformanceBenchmarkTest'`
  exercises keep-alive forwarding, fixed-length and chunked bodies, NTLM handshakes, an 8 MiB
  `CONNECT` echo (MB/s), a 32-client burst followed by idle pool drain, and header parsing, and
  reports elapsed time plus pool, fresh-connection and eviction counters. Run it repeatedly on the
  same JDK and machine when comparing changes; it is a regression signal, not a hardware-independent
  target.
- **Run locally:** activate the `local` profile — `application-local.yml` overrides `parents`,
  `flags`, and log levels for a real corporate proxy:
  ```shell
  ./gradlew bootRun --args='--spring.profiles.active=local'
  ```
- **Run the built jar / deploy:** use the `scripts/jntlm` control script (see below).

## Control script (`scripts/jntlm`)

A [jntlm](scripts/jntlm) script is the recommended POSIX control command for running JNTLM as a
background service. It resolves its own directory (`APP_HOME`) and expects three files side by side,
all sharing the script's base name:

```
<dir>/jntlm                     # the control script itself (may be symlinked; see below)
<dir>/jntlm.jar                 # the Spring Boot fat jar (from ./gradlew bootJar, may be symlinked)
<dir>/application-custom.yml    # your overrides (optional; see Configuration)
```

Commands (`APP_NAME` = "JNTLM Proxy Server"):

| Command   | Effect                                                                                                               |
|-----------|----------------------------------------------------------------------------------------------------------------------|
| `start`   | Verifies Java 21+, launches the jar detached, writes `jntlm.pid`, logs to `jntlm.log`.                               |
| `stop`    | Kills the PID, removes the pid file, and rotates `jntlm.log` to a timestamped file (purging logs older than 7 days). |
| `restart` | `stop` then `start`.                                                                                                 |
| `status`  | Reports whether the service is running (via the pid file), exits non-zero otherwise.                                 |
| `log`     | Opens the most recent log file with `less`.                                                                          |

It honors `JAVA_HOME` (falls back to `java` on `PATH`) and `JAVA_OPTS`
(default `-Xmx256m -server -Djava.awt.headless=true`).

### Linux / macOS

The script is native here — it uses `readlink -f`, `ps -p`, and `kill`:

```shell
chmod +x jntlm          # first time only
./jntlm start
./jntlm status
./jntlm log
./jntlm stop
```

> macOS note: the stock `readlink` lacks `-f`. Recent macOS ships a compatible `readlink`, but if
> resolution fails install GNU coreutils (`brew install coreutils`) and expose `greadlink` as
> `readlink` on `PATH`.

### Windows

There is no native `.bat`/`.ps1` wrapper; run the script from a **bash** environment. It already
detects Cygwin/MSYS/MinGW (`$OSTYPE`) and switches to `cygpath -w` for paths and `/bin/kill -W` for
stopping the process:

- **Git Bash / MSYS2 / Cygwin:** `./jntlm start`, `./jntlm status`, `./jntlm stop`.
- **WSL:** works as on Linux; use a Linux JDK inside the WSL distro.
- **Plain `cmd.exe` / PowerShell:** the script won't run directly — start the jar yourself:
  ```shell
  java --Xmx256m -server -Djava.awt.headless=true -jar jntlm.jar
  ```

## Configuration

Configured via `jntlm.*` properties (see `application.yml` for the annotated defaults):

| Property                              | Purpose                                                                                             |
|---------------------------------------|-----------------------------------------------------------------------------------------------------|
| `jntlm.listen-address`                | Local bind address (default `127.0.0.1`, loopback only).                                            |
| `jntlm.listen-port`                   | Local listener port (default `3128`).                                                               |
| `jntlm.auth`                          | NTLM dialect: `NTLMV2` (default), `NTLM2SR`, `NT`, `NTLM`, `LM`.                                    |
| `jntlm.flags`                         | Optional NTLM negotiate flags (hex/decimal; `0` = dialect default). With detection on, tried first. |
| `jntlm.detect.enabled`                | Auto-detect working negotiate flags (default `true`; see below).                                    |
| `jntlm.detect.probe-url`              | Optional URL probed at startup (`http` → `GET`, `https` → `CONNECT`).                               |
| `jntlm.parents`                       | Ordered `host:port` parent proxies with round-robin failover.                                       |
| `jntlm.credentials.*`                 | `username`, `domain`, `workstation`, and password/hashes.                                           |
| `jntlm.client-auth.enabled`           | Require BASIC proxy auth from clients (default `false`; see below).                                 |
| `jntlm.client-auth.realm`             | Realm in the `Proxy-Authenticate` challenge (default `jntlm`).                                      |
| `jntlm.client-auth.users`             | Accepted clients: `username` + `password` (plaintext or `{sha256}<hex>`).                           |
| `jntlm.limits.max-header-bytes`       | Max header section bytes per message (default `131072`); over → 431 (client) / 502 (parent).        |
| `jntlm.limits.max-header-count`       | Max header lines per message (default `256`); over → 431 (client) / 502 (parent).                   |
| `jntlm.limits.client-idle-timeout`    | Close an idle client connection after this long (default `300s`; `0` = never).                      |
| `jntlm.limits.parent-read-timeout`    | Parent silent this long → 504, or abort a body (default `600s`; `0` = never).                       |
| `jntlm.limits.tunnel-idle-timeout`    | Close a `CONNECT` tunnel idle in both directions (default `0` = never).                             |
| `jntlm.limits.max-client-connections` | Max concurrent client connections; extra ones get 503 (default `1024`; `0` = unlimited).            |
| `jntlm.pool.max-idle`                 | Max idle pooled parent connections; oldest closed beyond it (default `64`; `0` = no pooling).       |
| `jntlm.pool.idle-timeout`             | Close pooled parent connections idle this long (default `60s`; must be positive).                   |

Credentials: supply **either** a plaintext `password` (hashes derived at startup in `JntlmConfig`)
**or** pre-computed hex hashes (`pass-lm` / `pass-nt` / `pass-ntlm2`) — not both.

### Client authentication

By default anyone who can reach `listen-address:listen-port` can use the proxy (and thus your NTLM
identity). When you open the listener beyond `127.0.0.1`, enable BASIC client authentication:

```yaml
jntlm:
  client-auth:
    enabled: true
    realm: jntlm
    users:
    - username: alice
      password: "${JNTLM_ALICE_PASSWORD}"
    - username: bob
      # printf %s 'secret' | shasum -a 256
      password: "{sha256}2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
```

```shell
curl -x http://alice:secret@127.0.0.1:3128 https://example.com
```

- The first request on each client connection must carry valid `Proxy-Authorization: Basic ...`
  credentials; later keep-alive requests on the same connection are not re-checked. Otherwise jntlm
  replies `407` with `Proxy-Authenticate: Basic realm="..."` and closes the connection, without
  contacting the parent.
- Usernames are case-sensitive. The client's credentials are never forwarded to the parent proxy,
  and passwords are never logged (failed attempts are logged at WARN with address and username).
- Invalid configuration (no users, blank/duplicate username, blank password, malformed digest)
  stops startup.

> Caveat: BASIC sends credentials base64-encoded in **clear text**, and `{sha256}` digests are
> unsalted. This deters casual use on trusted networks; it is not a substitute for network-level
> protection.

### Hardening

Not in CNTLM — jntlm is stricter than its parser so that message boundaries are never ambiguous:

- Malformed client requests (e.g. `Header : value`, obs-fold, conflicting `Content-Length`,
  `Transfer-Encoding` + `Content-Length`, bad chunk sizes, missing `Host`) get `400 Bad Request` and
  the connection is closed; nothing reaches the parent.
- Oversized request headers get `431`; malformed or oversized parent responses get `502 Bad
  Gateway`; a parent silent for `parent-read-timeout` gets `504 Gateway Timeout`; an invalid NTLM
  challenge gets `502`. Over `max-client-connections`, new clients get `503` without contacting a
  parent.
- A parent connection is returned to the pool only after a cleanly framed exchange (explicit
  `Content-Length` or chunked, no `Connection: close`).
- The pool holds at most `jntlm.pool.max-idle` connections and closes any idle longer than
  `jntlm.pool.idle-timeout` (on reuse and by a background sweep), so parent-closed sockets do not
  linger in `CLOSE_WAIT`. If a reused pooled connection turns out to be closed, a body-less request
  is retried on a fresh connection; a request with a body (which cannot be replayed) gets `502 Bad
  Gateway` instead of a silent close.
- At startup, a WARN is logged when the listener is reachable from other hosts (non-loopback
  `listen-address`) while client authentication is disabled.
- Each timeout is disabled with `0` (e.g. `jntlm.limits.client-idle-timeout: 0`), and
  `max-client-connections: 0` removes the connection cap.

### Flag auto-detection

Many parent proxies reject the default NTLM negotiate flags for a dialect (e.g. `0xa208b205` for
NTLMv2). By default, jntlm finds a working set itself:

- It probes the parent with up to 8 candidates: `jntlm.flags` (if set), the dialect default, then
  progressively reduced variants (e.g. `0x00088205`), plus a variant derived from the flags the
  parent advertises in its challenge. A candidate wins only if the full NTLM handshake succeeds.
- Detection runs once — at startup if `jntlm.detect.probe-url` is set, otherwise on the first client
  request (as a body-less `GET`, or `CONNECT` for tunnels). Concurrent requests wait for it.
- The result is cached and logged at INFO (`Detected NTLM flags 0x... for parent ...`), so you can
  pin it in `jntlm.flags`. It is re-detected after a parent failover, or when the cached flags are
  rejected (at most once per 60s).
- If nothing works, jntlm falls back to the dialect default.

> Notes: detection opens a few extra short-lived connections to the parent, and a lazy probe sends
> one extra `GET` to the first requested URL. With a wrong password every candidate fails at the
> final handshake step, which some proxies count toward account lockout. Set
> `jntlm.detect.enabled: false` to restore the static behavior (`jntlm.flags` or the dialect
> default, no probing).

### User overrides via the `custom` profile

The bundled `application.yml` sets `spring.profiles.include: custom`, so Spring Boot **always**
loads a user-defined `application-custom` config alongside the defaults, and its values win. Drop an
`application-custom.yml` (or `.yaml`, or `.properties`) next to the jar and override only what you
need — you never have to edit the packaged defaults:

```yaml
# application-custom.yml
jntlm:
  flags: "0x00088205"
  parents: proxy.example.com:8080

logging.level:
  net.domax.jntlm: DEBUG
```

(The `scripts/jntlm` control script expects this file beside `jntlm.jar`. During development the
separate `local` profile — `application-local.yml`, excluded from the jar — plays the same role via
`--spring.profiles.active=local`.)

## Project-specific conventions

- **CNTLM parity is the prime directive.** Most classes cite the exact CNTLM C function they port
  (e.g. `forward.c`'s `forward_request`, `proxy.c`'s `proxy_authenticate`). Preserve that behavior;
  Javadoc the CNTLM source when adding logic. Don't "modernize" the control flow casually.
- **Lombok everywhere:** `val`/`var`, `@Data`, `@Slf4j`, `@RequiredArgsConstructor`, `@Getter`,
  `@Accessors(fluent = true)` (note fluent accessors, e.g. `endpoint.in()`, not `getIn()`).
- **Version single source of truth:** `jntlm.version` in `src/main/resources/application.yml`.
  `build.gradle` parses it to set the Gradle `version`; do not hardcode versions elsewhere.
- Every `.java` file starts with the header `/* JNTLM © Licensed under MIT $YEAR. */` (enforced by
  Spotless).
- Not a web app: no controllers/MVC. Networking is raw `Socket`/`ServerSocket` + virtual threads.

## Gotchas

- NTLM negotiate `flags` sometimes need per-proxy overrides (some proxies reject the default
  `0xa208b205`). `NtlmFlagsResolver` auto-detects a working set on first use (see "Flag
  auto-detection"); `jntlm.flags` pins one (e.g. `0x00088205` for BlueCoat, see the annotated
  `application-local.yml`).
- Credentials: supply either a plaintext `password` (hashes derived at startup in `JntlmConfig`)
  **or** pre-computed hex hashes (`pass-lm` / `pass-nt` / `pass-ntlm2`) — not both.
- A previously tolerated but invalid message now fails with `400`/`502` (see "Hardening"); slow
  transfers may hit `jntlm.limits.*` timeouts, which can be raised or set to `0`.

## License

[MIT](LICENSE.txt)
