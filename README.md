# jntlm

A Java 21 / Spring Boot rewrite of the [CNTLM](https://cntlm.sourceforge.net/)
NTLM-authenticating HTTP proxy. It listens locally (unauthenticated) and transparently performs the
NTLM handshake to a corporate parent proxy, so tools that cannot speak NTLM themselves can reach the
internet through the local port.

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
      `ForwardResult.Type.REROUTE`.
* `proxy/`:
    - `RequestForwarder` is the core engine (a faithful port of CNTLM's `forward_request`; keep the
      labeled two-pass `loop 0 = client→parent`, `loop 1 = parent→client` structure).
    - `ProxyAuthenticator` runs the NTLM 407 handshake;
    - `ConnectionPool` caches already-authenticated parent connections (NTLM auth is bound to a TCP
      connection, so reuse skips re-auth);
    - `ParentProxyManager` does round-robin failover over `jntlm.parents`.
* `ntlm/` — pure NTLM crypto/message building (`NtlmMessages`, `NtlmHashes`, `NtlmCrypto`, `Md4`).
  All multibyte fields are **little-endian** (`Le`). `Credentials` holds dialect switches + hashes.
* `http/` — hand-rolled HTTP wire I/O (`HttpIo`, `HttpMessage`, `HttpHeaders`); no servlet stack.
* `config/`:
    - `JntlmProperties` (`@ConfigurationProperties(prefix="jntlm")`) + `JntlmConfig`
      builds the global `Credentials` bean;
    - `AuthMode` maps dialects to hash switches.

## Project layout

```
src/main/java/net/domax/jntlm/
├── JntlmApplication.java        # Spring Boot entry point (writes a PID file)
├── config/                      # JntlmProperties, JntlmConfig, AuthMode
├── server/                      # ProxyServer, ClientConnectionHandler
├── proxy/                       # RequestForwarder, ProxyAuthenticator, ConnectionPool,
│                                #   ParentProxyManager, Endpoint, ForwardResult, ErrorPages
├── ntlm/                        # NtlmMessages, NtlmHashes, NtlmCrypto, Md4, Le, Credentials
└── http/                        # HttpIo, HttpMessage, HttpHeaders
src/main/resources/
├── application.yml              # Defaults + jntlm.version (single source of truth)
├── application-local.yml        # Local dev overrides (excluded from the boot jar)
└── banner.txt
bin/jntlm                        # start/stop/restart/status/log control script
```

## Developer workflows

- **Build:** `./gradlew build` — Java 21 toolchain, Spring Boot 4.
- **Format (required before commit):** `./gradlew spotlessApply` (google-java-format 1.27 + license
  header).
- **Test:** `./gradlew test` (JUnit 5 + Mockito, JaCoCo report at
  `build/reports/jacoco/test/html`). See `ProxyForwardingIntegrationTest` for the pattern: an in-JVM
  `MockParentProxy` speaking the NTLM 407 handshake; wire real components manually
  (`new RequestForwarder(manager, pool, auth, creds)`).
- **Run locally:** activate the `local` profile — `application-local.yml` overrides `parents`,
  `flags`, and log levels for a real corporate proxy:
  ```bash
  ./gradlew bootRun --args='--spring.profiles.active=local'
  ```
- **Run the built jar / deploy:** use the `bin/jntlm` control script (see below).

## Control script (`bin/jntlm`)

`bin/jntlm` is the recommended POSIX control command for running JNTLM as a background service. It
resolves its own directory (`APP_HOME`) and expects three files side by side, all sharing the
script's base name:

```
<dir>/jntlm                     # the control script itself (may be symlinked; see below)
<dir>/jntlm.jar                 # the Spring Boot fat jar (from ./gradlew bootJar, may be symlinked)
<dir>/application-custom.yml    # your overrides (optional; see Configuration)
```

Commands (`APP_NAME` = "JNTLM Proxy Server"):

| Command   | Effect                                                                                                               |
|-----------|----------------------------------------------------------------------------------------------------------------------|
| `start`   | Verifies Java 21+, launches the jar detached, writes `jntlm.pid`, logs to `jntlm.log`.                               |
| `stop`    | Kills the PID, removes the pid file, and rotates `jntlm.log` to a timestamped file (purging logs older than 6 days). |
| `restart` | `stop` then `start`.                                                                                                 |
| `status`  | Reports whether the service is running (via the pid file), exits non-zero otherwise.                                 |
| `log`     | Opens the most recent log file with `less`.                                                                          |

It honors `JAVA_HOME` (falls back to `java` on `PATH`) and `JAVA_OPTS`
(default `-Xmx256m -server -Djava.awt.headless=true`).

### Linux / macOS

The script is native here — it uses `readlink -f`, `ps -p`, and `kill`:

```bash
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
  ```powershell
  java --Xmx256m -server -Djava.awt.headless=true -jar jntlm.jar
  ```

## Configuration

Configured via `jntlm.*` properties (see `application.yml` for the annotated defaults):

| Property               | Purpose                                                          |
|------------------------|------------------------------------------------------------------|
| `jntlm.listen-address` | Local bind address (default `127.0.0.1`, loopback only).         |
| `jntlm.listen-port`    | Local listener port (default `3128`).                            |
| `jntlm.auth`           | NTLM dialect: `NTLMV2` (default), `NTLM2SR`, `NT`, `NTLM`, `LM`. |
| `jntlm.flags`          | Optional manual NTLM negotiate flags (hex/decimal; `0` = auto).  |
| `jntlm.parents`        | Ordered `host:port` parent proxies with round-robin failover.    |
| `jntlm.credentials.*`  | `username`, `domain`, `workstation`, and password/hashes.        |

Credentials: supply **either** a plaintext `password` (hashes derived at startup in `JntlmConfig`)
**or** pre-computed hex hashes (`pass-lm` / `pass-nt` / `pass-ntlm2`) — not both.

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

(The `bin/jntlm` control script expects this file beside `jntlm.jar`. During development the
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
  `0xa208b205`); see the annotated `application-local.yml` example (`0x00088205` for BlueCoat).
- Credentials: supply either a plaintext `password` (hashes derived at startup in `JntlmConfig`)
  **or** pre-computed hex hashes (`pass-lm` / `pass-nt` / `pass-ntlm2`) — not both.

## License

[MIT](LICENSE.txt).
