/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.config;

import static java.util.Optional.ofNullable;
import static java.util.function.Predicate.not;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.ntlm.Credentials;
import net.domax.jntlm.ntlm.NtlmHashes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Builds the global NTLM {@link Credentials} bean from {@link JntlmProperties}.
 *
 * <p>Ports the credential-preparation logic from CNTLM's {@code main.c}: {@code user@domain}
 * splitting, defaulting the workstation to the local hostname, deriving the LM/NT/NTLMv2 hashes
 * from a plaintext password, or accepting pre-computed hex hashes.
 */
@Slf4j
@Configuration
public class JntlmConfig {

  /** Creates a virtual-thread-per-task executor for handling client connections. */
  @Bean
  ExecutorService clientExecutor() {
    return Executors.newThreadPerTaskExecutor(
        Thread.ofVirtual().name("jntlm-client-", 0).factory());
  }

  /** Creates the global NTLM credentials from the configured properties. */
  @Bean
  public Credentials globalCredentials(JntlmProperties properties) {
    val src = properties.getCredentials();
    val creds = new Credentials().setUser("").setDomain(ofNullable(src.getDomain()).orElse(""));

    ofNullable(src.getUsername())
        // Split "user@domain" - the domain part overrides the Domain setting.
        .map(u -> u.split("@", 2))
        .map(p -> p.length == 2 ? p : new String[] {p[0], creds.getDomain()})
        .ifPresent(p -> creds.setUser(p[0]).setDomain(p[1]));

    creds.setWorkstation(
        ofNullable(src.getWorkstation())
            .filter(not(String::isBlank))
            .orElseGet(JntlmConfig::defaultWorkstation));

    // Select the dialect (sets hashNt/hashLm/hashNtlm2) and optional manual flags.
    properties.getAuth().applyTo(creds).setFlags(parseFlags(properties.getFlags()));

    ofNullable(src.getPassword())
        .filter(not(String::isBlank))
        .ifPresentOrElse(
            // Derive every hash the configured dialect might need from the plaintext password.
            p ->
                creds
                    .setPassLm(NtlmHashes.lmHash(p))
                    .setPassNt(NtlmHashes.ntHash(p))
                    .setPassNtlm2(NtlmHashes.ntlm2Hash(creds.getUser(), creds.getDomain(), p)),
            () ->
                creds
                    .setPassLm(parseHash(src.getPassLm()).orElse(null))
                    .setPassNt(parseHash(src.getPassNt()).orElse(null))
                    .setPassNtlm2(parseHash(src.getPassNtlm2()).orElse(null)));

    log.debug("Credential success: {}", creds);
    return creds;
  }

  /** Returns the local hostname (without a domain) or "jntlm" if it cannot be determined. */
  private static String defaultWorkstation() {
    val defHost = "jntlm";
    try {
      val host =
          ofNullable(InetAddress.getLocalHost().getHostName())
              .map(h -> h.replaceFirst("\\..+$", ""))
              .filter(not(String::isBlank))
              .orElse(defHost);
      log.info("Using default workstation: {}", host);
      return host;
    } catch (UnknownHostException ignored) {
      log.warn("Could not determine workstation. Defaulting to '{}'", defHost);
      return defHost;
    }
  }

  /**
   * Parses the optional NTLM negotiate-flags override. Accepts a hexadecimal ({@code 0x...}) or
   * decimal string; blank/{@code null} yields {@code 0} (use the per-dialect default).
   */
  private static long parseFlags(String flags) {
    return ofNullable(flags)
        .map(String::trim)
        .filter(not(String::isEmpty))
        .map(Long::decode)
        .orElse(0L);
  }

  /** Parses a 32-char hex string into a 16-byte hash, or returns empty {@link Optional} if blank */
  private static Optional<byte[]> parseHash(String hex) {
    return ofNullable(hex)
        .map(String::trim)
        .filter(not(String::isEmpty))
        .map(HexFormat.of()::parseHex);
  }
}
