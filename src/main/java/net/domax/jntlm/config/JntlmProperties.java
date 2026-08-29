/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.config;

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
   * Optional manual NTLM negotiate-flags override (blank/{@code 0} = use built-in per-dialect
   * default). Accepts hexadecimal ({@code 0x...}) or decimal, mirroring CNTLM's {@code Flags}
   * directive.
   */
  private String flags;

  /** Ordered list of parent proxies ({@code host:port}) tried with failover. */
  private List<String> parents = new ArrayList<>();

  private Credentials credentials = new Credentials();

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
