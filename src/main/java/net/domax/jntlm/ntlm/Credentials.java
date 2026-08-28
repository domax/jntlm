/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

import static java.util.Optional.ofNullable;

import lombok.Data;
import lombok.ToString.Exclude;
import lombok.val;

/**
 * NTLM credentials and dialect selection for authenticating to a parent proxy.
 *
 * <p>Mirrors CNTLM's {@code struct auth_s}. Holds the identity (user, domain, workstation), the
 * three pre-computed 16-byte password hashes, the dialect switches ({@link #hashNt}, {@link
 * #hashLm}, {@link #hashNtlm2}) and an optional manual negotiate-flags override.
 *
 * <p>The dialect switches follow CNTLM semantics:
 *
 * <ul>
 *   <li>{@code hashNtlm2 == 1} &rarr; NTLMv2
 *   <li>{@code hashNt == 2} &rarr; NTLM2 session response (NTLM2SR)
 *   <li>{@code hashNt == 1 && hashLm == 1} &rarr; combined NT+LM (NTLM)
 *   <li>{@code hashNt == 1} &rarr; NT only
 *   <li>{@code hashLm == 1} &rarr; LM only
 * </ul>
 */
@Data
public final class Credentials {

  private String user = "";
  private String domain = "";
  private String workstation = "";

  @Exclude private byte[] passLm;
  @Exclude private byte[] passNt;
  @Exclude private byte[] passNtlm2;

  private int hashNt;
  private int hashLm;
  private int hashNtlm2;

  /** Optional manual NTLM negotiate flags; {@code 0} means "use the built-in default". */
  private long flags;

  /** Returns a deep copy of these credentials (used per client-connection thread). */
  public Credentials copy() {
    val c = new Credentials();
    c.user = user;
    c.domain = domain;
    c.workstation = workstation;
    c.passLm = ofNullable(passLm).map(byte[]::clone).orElse(null);
    c.passNt = ofNullable(passNt).map(byte[]::clone).orElse(null);
    c.passNtlm2 = ofNullable(passNtlm2).map(byte[]::clone).orElse(null);
    c.hashNt = hashNt;
    c.hashLm = hashLm;
    c.hashNtlm2 = hashNtlm2;
    c.flags = flags;
    return c;
  }
}
