/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

import static java.lang.System.arraycopy;
import static net.domax.jntlm.ntlm.NtlmCrypto.desEncryptBlock;
import static net.domax.jntlm.ntlm.NtlmCrypto.hmacMd5;
import static net.domax.jntlm.ntlm.NtlmCrypto.md4;
import static net.domax.jntlm.ntlm.NtlmCrypto.toUnicode;

import lombok.val;

/**
 * Computes the NTLM password hashes.
 *
 * <p>Ports CNTLM's {@code ntlm_hash_lm_password}, {@code ntlm_hash_nt_password} and {@code
 * ntlm2_hash_password} from {@code ntlm.c}. Each hash is a 16-byte value.
 */
public final class NtlmHashes {

  /** The fixed "KGS!@#$%" magic block DES-encrypted to derive the LM hash. */
  private static final byte[] LM_MAGIC = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};

  private NtlmHashes() {}

  /**
   * Computes the 16-byte LM hash of a password. The password is upper-cased, truncated to 14 bytes
   * (OEM charset) and split into two 7-byte DES keys used to encrypt the magic block.
   */
  public static byte[] lmHash(String password) {
    val oem = NtlmCrypto.toOem(password.toUpperCase());
    val pass = new byte[14];
    arraycopy(oem, 0, pass, 0, Math.min(14, oem.length));

    val out = new byte[16];
    arraycopy(desEncryptBlock(pass, 0, LM_MAGIC), 0, out, 0, 8);
    arraycopy(desEncryptBlock(pass, 7, LM_MAGIC), 0, out, 8, 8);
    return out;
  }

  /** Computes the 16-byte NT hash: MD4 of the UTF-16LE password. */
  public static byte[] ntHash(String password) {
    return md4(toUnicode(password));
  }

  /**
   * Computes the 16-byte NTLMv2 hash (also called NTOWFv2): HMAC-MD5 keyed by the NT hash over the
   * UTF-16LE of upper-cased(username + domain).
   */
  public static byte[] ntlm2Hash(String username, String domain, String password) {
    return hmacMd5(ntHash(password), toUnicode((username + domain).toUpperCase()));
  }
}
