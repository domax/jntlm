/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import lombok.val;

/**
 * NTLM negotiate flags (MS-NLMP 2.2.2.5): per-dialect defaults, detection candidates and helpers.
 *
 * <p>The per-dialect defaults are the values CNTLM's {@code ntlm_request} ({@code ntlm.c}) picks
 * when no manual {@code Flags} override is configured.
 */
public final class NtlmFlags {

  public static final long NEGOTIATE_56 = 0x80000000L;
  public static final long NEGOTIATE_128 = 0x20000000L;
  public static final long NEGOTIATE_VERSION = 0x02000000L;
  public static final long NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000L;
  public static final long ALWAYS_SIGN = 0x00008000L;
  public static final long NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000L;
  public static final long NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000L;
  public static final long NTLM = 0x00000200L;
  public static final long REQUEST_TARGET = 0x00000004L;
  public static final long NEGOTIATE_OEM = 0x00000002L;
  public static final long UNICODE = 0x00000001L;

  /** Base negotiate flags common to all dialects ({@code 0xb204}). */
  private static final long BASE_FLAGS =
      ALWAYS_SIGN
          | NEGOTIATE_OEM_WORKSTATION_SUPPLIED
          | NEGOTIATE_OEM_DOMAIN_SUPPLIED
          | NTLM
          | REQUEST_TARGET;

  /** Default negotiate flags for the NTLMv2 dialect ({@code 0xa208b205}). */
  public static final long NTLMV2_FLAGS =
      BASE_FLAGS
          | NEGOTIATE_56
          | NEGOTIATE_128
          | NEGOTIATE_VERSION
          | NEGOTIATE_EXTENDED_SESSION_SECURITY
          | UNICODE;

  /** Default negotiate flags for the NTLM2 session-response dialect ({@code 0xa208b207}). */
  public static final long NTLM2SR_FLAGS = NTLMV2_FLAGS | NEGOTIATE_OEM;

  /** Default negotiate flags for the NT-only dialect ({@code 0xb205}). */
  public static final long NT_FLAGS = BASE_FLAGS | UNICODE;

  /** Default negotiate flags for the LM-only dialect ({@code 0xb206}). */
  public static final long LM_FLAGS = BASE_FLAGS | NEGOTIATE_OEM;

  /** Default negotiate flags for the combined NT+LM dialect ({@code 0xb207}). */
  public static final long NTLM_FLAGS = NT_FLAGS | LM_FLAGS;

  private static final long CHARSET_MASK = UNICODE | NEGOTIATE_OEM;

  private NtlmFlags() {}

  /**
   * Returns the built-in negotiate flags for the dialect selected on {@code creds}, ignoring any
   * manual {@code creds.flags} override.
   */
  public static long defaultFor(Credentials creds) {
    if (creds.getHashNtlm2() != 0) return NTLMV2_FLAGS;
    if (creds.getHashNt() == 2) return NTLM2SR_FLAGS;
    if (creds.getHashNt() != 0 && creds.getHashLm() != 0) return NTLM_FLAGS;
    if (creds.getHashNt() != 0) return NT_FLAGS;
    if (creds.getHashLm() != 0) return LM_FLAGS;
    throw new IllegalStateException("No NTLM hash configured in credentials");
  }

  /**
   * Returns the ordered, de-duplicated detection candidates: the explicit flags (if non-zero), the
   * dialect default, then progressively reduced variants of the default.
   */
  public static List<Long> candidates(Credentials creds, long explicitFlags) {
    val d = defaultFor(creds);
    val v1 = d & ~(NEGOTIATE_56 | NEGOTIATE_128 | NEGOTIATE_VERSION);
    val v2 = v1 & ~(NEGOTIATE_OEM_DOMAIN_SUPPLIED | NEGOTIATE_OEM_WORKSTATION_SUPPLIED);
    val v3 = v2 & ~ALWAYS_SIGN;
    val v4 = v3 & ~NEGOTIATE_EXTENDED_SESSION_SECURITY;

    val set = new LinkedHashSet<Long>();
    for (long f : new long[] {explicitFlags, d, v1, v2, v3, v4}) if (f != 0) set.add(f);
    return new ArrayList<>(set);
  }

  /** Reads the server's negotiate flags (little-endian u32 at offset 20) from a Type-2 message. */
  public static long fromChallenge(byte[] type2) {
    if (type2 == null || type2.length < 24) return 0;
    return Le.readU16(type2, 20) | ((long) Le.readU16(type2, 22) << 16);
  }

  /**
   * Derives a candidate from a rejected one and the flags the server advertised in its Type-2:
   * {@code candidate & serverFlags}. Returns {@code 0} when the result is unusable (zero, lacks
   * {@link #NTLM}, or drops a charset bit the candidate had).
   */
  @SuppressWarnings("unused") // creds kept for dialect-aware refinement per design D1
  public static long refine(long candidate, long serverFlags, Credentials creds) {
    val r = candidate & serverFlags;
    if (r == 0 || (r & NTLM) == 0) return 0;
    val charset = candidate & CHARSET_MASK;
    return (r & charset) == charset ? r : 0;
  }

  /** Formats flags as {@code 0x%08x}. */
  public static String hex(long flags) {
    return String.format("0x%08x", flags);
  }
}
