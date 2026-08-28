/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

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
public final class Credentials {

  private String user = "";
  private String domain = "";
  private String workstation = "";

  private byte[] passLm;
  private byte[] passNt;
  private byte[] passNtlm2;

  private int hashNt;
  private int hashLm;
  private int hashNtlm2;

  /** Optional manual NTLM negotiate flags; {@code 0} means "use the built-in default". */
  private long flags;

  /** Returns a deep copy of these credentials (used per client-connection thread). */
  public Credentials copy() {
    Credentials c = new Credentials();
    c.user = user;
    c.domain = domain;
    c.workstation = workstation;
    c.passLm = passLm == null ? null : passLm.clone();
    c.passNt = passNt == null ? null : passNt.clone();
    c.passNtlm2 = passNtlm2 == null ? null : passNtlm2.clone();
    c.hashNt = hashNt;
    c.hashLm = hashLm;
    c.hashNtlm2 = hashNtlm2;
    c.flags = flags;
    return c;
  }

  public String getUser() {
    return user;
  }

  public void setUser(String user) {
    this.user = user == null ? "" : user;
  }

  public String getDomain() {
    return domain;
  }

  public void setDomain(String domain) {
    this.domain = domain == null ? "" : domain;
  }

  public String getWorkstation() {
    return workstation;
  }

  public void setWorkstation(String workstation) {
    this.workstation = workstation == null ? "" : workstation;
  }

  public byte[] getPassLm() {
    return passLm;
  }

  public void setPassLm(byte[] passLm) {
    this.passLm = passLm;
  }

  public byte[] getPassNt() {
    return passNt;
  }

  public void setPassNt(byte[] passNt) {
    this.passNt = passNt;
  }

  public byte[] getPassNtlm2() {
    return passNtlm2;
  }

  public void setPassNtlm2(byte[] passNtlm2) {
    this.passNtlm2 = passNtlm2;
  }

  public int getHashNt() {
    return hashNt;
  }

  public void setHashNt(int hashNt) {
    this.hashNt = hashNt;
  }

  public int getHashLm() {
    return hashLm;
  }

  public void setHashLm(int hashLm) {
    this.hashLm = hashLm;
  }

  public int getHashNtlm2() {
    return hashNtlm2;
  }

  public void setHashNtlm2(int hashNtlm2) {
    this.hashNtlm2 = hashNtlm2;
  }

  public long getFlags() {
    return flags;
  }

  public void setFlags(long flags) {
    this.flags = flags;
  }
}
