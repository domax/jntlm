/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.config;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

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
