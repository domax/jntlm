/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

/**
 * An NTLM message that cannot be parsed or built (invalid Type-2 challenge, or a Type-3 field that
 * does not fit its 16-bit length). Not in CNTLM, which reads such input without bounds checks.
 */
public final class NtlmException extends RuntimeException {

  public NtlmException(String message) {
    super(message);
  }
}
