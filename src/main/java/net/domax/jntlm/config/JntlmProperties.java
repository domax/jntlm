/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.config;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;

/**
 * Typed configuration for jntlm, bound from the {@code jntlm.*} properties.
 *
 * <p>Replaces CNTLM's {@code cntlm.conf} options relevant to the core proxy: listen address, NTLM
 * credentials, authentication dialect and the list of parent proxies.
 */
@Data
@ConfigurationProperties(prefix = "jntlm")
public class JntlmProperties {

  /** Version string, bound from {@code jntlm.version}. */
  private String version = "0.0.0";

  /** Local address to bind the proxy listener to. Default loopback only. */
  private String listenAddress = "127.0.0.1";

  /** Local TCP port the proxy listens on. */
  private int listenPort = 3128;

  /** NTLM authentication dialect used towards the parent proxy. */
  private AuthMode auth = AuthMode.NTLMV2;

  /**
   * Optional manual NTLM negotiate flags (blank/{@code 0} = use built-in per-dialect default).
   * Accepts hexadecimal ({@code 0x...}) or decimal, mirroring CNTLM's {@code Flags} directive. When
   * flags auto-detection is enabled, this value is the first candidate tried.
   */
  private String flags;

  /** NTLM negotiate-flags auto-detection settings, bound from {@code jntlm.detect.*}. */
  private Detect detect = new Detect();

  /** Ordered list of parent proxies ({@code host:port}) tried with failover. */
  private List<String> parents = new ArrayList<>();

  private Credentials credentials = new Credentials();

  /** Optional BASIC authentication of incoming clients, bound from {@code jntlm.client-auth.*}. */
  private ClientAuth clientAuth = new ClientAuth();

  /** Header-size limits, timeouts and connection cap, bound from {@code jntlm.limits.*}. */
  private Limits limits = new Limits();

  /** Idle parent-connection pool bounds, bound from {@code jntlm.pool.*}. */
  private Pool pool = new Pool();

  /**
   * Bounds of the pool of idle, already-authenticated parent connections. Not in CNTLM: CNTLM's
   * {@code connection_list} is unbounded and never evicts idle entries.
   */
  @Data
  public static class Pool {

    /** Maximum number of idle pooled parent connections; {@code 0} disables pooling. */
    private int maxIdle = 64;

    /** Idle pooled connections older than this are closed instead of reused (must be positive). */
    private Duration idleTimeout = Duration.ofSeconds(60);
  }

  /**
   * Resource limits protecting the proxy from oversized messages, stalled peers and connection
   * floods. Not in CNTLM. A zero duration or connection count disables that limit; header limits
   * must be positive.
   */
  @Data
  public static class Limits {

    /** Maximum size of a request or response header section (incl. line terminators). */
    private DataSize maxHeaderSize = DataSize.ofKilobytes(128);

    /** Maximum number of header lines in a request or response (and chunked trailers). */
    private int maxHeaderCount = 256;

    /** Read timeout on client connections (waiting for a request or its body); 0 = none. */
    private Duration clientIdleTimeout = Duration.ofSeconds(300);

    /** Read timeout on parent connections (waiting for response headers or body); 0 = none. */
    private Duration parentReadTimeout = Duration.ofSeconds(600);

    /** Idle timeout of a CONNECT tunnel (no bytes in either direction); 0 = none. */
    private Duration tunnelIdleTimeout = Duration.ZERO;

    /** Maximum concurrent client connections; extra ones get {@code 503}. 0 = unlimited. */
    private int maxClientConnections = 1024;
  }

  /**
   * Optional HTTP BASIC proxy authentication required from clients connecting to the jntlm
   * listener. Not in CNTLM: a jntlm-only addition.
   */
  @Data
  public static class ClientAuth {

    /** Whether clients must authenticate. Default {@code false} (open listener, as in CNTLM). */
    private boolean enabled = false;

    /** Realm advertised in the {@code Proxy-Authenticate: Basic realm="..."} challenge. */
    private String realm = "jntlm";

    /** Accepted client accounts. */
    private List<User> users = new ArrayList<>();
  }

  /**
   * A client account. The {@code password} is either plaintext or {@code {sha256}<hex>} (the hex
   * SHA-256 digest of the UTF-8 password).
   */
  @Data
  public static class User {

    /** Client username (case-sensitive, must not contain {@code :}). */
    private String username = "";

    /** Plaintext password or {@code {sha256}<64 hex digits>}. */
    @ToString.Exclude private String password = "";
  }

  /** NTLM negotiate-flags auto-detection settings. */
  @Data
  public static class Detect {

    /**
     * Whether to probe the parent proxy for working NTLM negotiate flags. When {@code false}, the
     * explicit {@code jntlm.flags} (or the per-dialect default) is used without probing.
     */
    private boolean enabled = true;

    /**
     * Optional URL probed at startup ({@code http://} via {@code GET}, {@code https://} via {@code
     * CONNECT}). When blank, detection runs lazily on the first client request.
     */
    private URI probeUrl;
  }

  /**
   * Raw credential settings bound from {@code jntlm.credentials.*}. Either a plaintext {@code
   * password} or the pre-computed hex hashes may be supplied.
   */
  @Data
  public static class Credentials {

    /** Proxy account username (could be given as {@code user@domain}). */
    private String username = "";

    /** NT domain / workgroup. */
    private String domain = "";

    /** NetBIOS workstation name; defaults to the local hostname when blank. */
    private String workstation = "";

    /** Plaintext password (optional if hashes are supplied). */
    private String password = "";

    /** Pre-computed LM hash as a 32-char hex string. */
    private String passLm = "";

    /** Pre-computed NT hash as a 32-char hex string. */
    private String passNt = "";

    /** Pre-computed NTLMv2 hash as a 32-char hex string (tied to a specific user+domain). */
    private String passNtlm2 = "";
  }
}
