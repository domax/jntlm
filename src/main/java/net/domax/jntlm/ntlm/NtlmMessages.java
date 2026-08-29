/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

import static java.lang.System.arraycopy;
import static net.domax.jntlm.ntlm.NtlmCrypto.desEncryptBlock;
import static net.domax.jntlm.ntlm.NtlmCrypto.toOem;
import static net.domax.jntlm.ntlm.NtlmCrypto.toUnicode;

import java.security.SecureRandom;
import java.util.Arrays;
import lombok.val;

/**
 * Builds NTLM Type-1 (negotiate) and Type-3 (authenticate) messages and computes the challenge
 * responses.
 *
 * <p>Direct port of CNTLM's {@code ntlm_request} and {@code ntlm_response} (plus the {@code
 * ntlm_calc_resp}, {@code ntlm2_calc_resp} and {@code ntlm2sr_calc_rest} helpers) from {@code
 * ntlm.c}. All multibyte fields are little-endian.
 */
public final class NtlmMessages {

  /** Minimum Type-2 challenge length for which a target-info block is parsed. */
  private static final int NTLM_CHALLENGE_MIN = 40;

  private static final int NTLM_BUFSIZE = 1024;

  /** Offset between the Unix epoch and the Windows FILETIME epoch (1601), in seconds. */
  private static final long FILETIME_EPOCH_OFFSET = 11644473600L;

  // Individual NTLM negotiate flags (MS-NLMP).
  private static final long NEGOTIATE_56 = 0x80000000L;
  private static final long NEGOTIATE_128 = 0x20000000L;
  private static final long NEGOTIATE_VERSION = 0x02000000L;
  private static final long NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000L;
  private static final long ALWAYS_SIGN = 0x00008000L;
  private static final long NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000L;
  private static final long NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000L;
  private static final long NTLM = 0x00000200L;
  private static final long REQUEST_TARGET = 0x00000004L;
  private static final long NEGOTIATE_OEM = 0x00000002L;
  private static final long UNICODE = 0x00000001L;

  /** Base negotiate flags common to all dialects ({@code 0xb204}). */
  private static final long BASE_FLAGS =
      ALWAYS_SIGN
          | NEGOTIATE_OEM_WORKSTATION_SUPPLIED
          | NEGOTIATE_OEM_DOMAIN_SUPPLIED
          | NTLM
          | REQUEST_TARGET;

  /** Default negotiate flags for the NTLMv2 dialect ({@code 0xa208b205}). */
  private static final long NTLMV2_FLAGS =
      BASE_FLAGS
          | NEGOTIATE_56
          | NEGOTIATE_128
          | NEGOTIATE_VERSION
          | NEGOTIATE_EXTENDED_SESSION_SECURITY
          | UNICODE;

  /** Default negotiate flags for the NTLM2 session-response dialect ({@code 0xa208b207}). */
  private static final long NTLM2SR_FLAGS = NTLMV2_FLAGS | NEGOTIATE_OEM;

  /** Default negotiate flags for the NT-only dialect ({@code 0xb205}). */
  private static final long NT_FLAGS = BASE_FLAGS | UNICODE;

  /** Default negotiate flags for the LM-only dialect ({@code 0xb206}). */
  private static final long LM_FLAGS = BASE_FLAGS | NEGOTIATE_OEM;

  /** Default negotiate flags for the combined NT+LM dialect ({@code 0xb207}). */
  private static final long NTLM_FLAGS = NT_FLAGS | LM_FLAGS;

  private static final SecureRandom RANDOM = new SecureRandom();

  private NtlmMessages() {}

  /**
   * Builds the NTLM Type-1 (negotiate) message. Mirrors {@code ntlm_request}: the domain and
   * workstation are sent upper-cased in the OEM charset, and the default per-dialect negotiate
   * flags are chosen unless {@code creds.flags} overrides them.
   */
  public static byte[] type1Request(Credentials creds) {
    val flags = getFlags(creds);

    val domain = toOem(creds.getDomain().toUpperCase());
    val host = toOem(creds.getWorkstation().toUpperCase());
    val dlen = domain.length;
    val hlen = host.length;

    val buf = new byte[32 + dlen + hlen];
    arraycopy("NTLMSSP\0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), 0, buf, 0, 8);
    Le.u32(buf, 8, 1);
    Le.u32(buf, 12, flags);
    Le.u16(buf, 16, dlen);
    Le.u16(buf, 18, dlen);
    Le.u32(buf, 20, 32L + hlen);
    Le.u16(buf, 24, hlen);
    Le.u16(buf, 26, hlen);
    Le.u32(buf, 28, 32);
    arraycopy(host, 0, buf, 32, hlen);
    arraycopy(domain, 0, buf, 32 + hlen, dlen);
    return buf;
  }

  private static long getFlags(Credentials creds) {
    if (creds.getFlags() != 0) return creds.getFlags();
    if (creds.getHashNtlm2() != 0) return NTLMV2_FLAGS;
    if (creds.getHashNt() == 2) return NTLM2SR_FLAGS;
    if (creds.getHashNt() != 0 && creds.getHashLm() != 0) return NTLM_FLAGS;
    if (creds.getHashNt() != 0) return NT_FLAGS;
    if (creds.getHashLm() != 0) return LM_FLAGS;
    throw new IllegalStateException("No NTLM hash configured in credentials");
  }

  /**
   * Builds the NTLM Type-3 (authenticate) message in response to the given Type-2 challenge.
   * Mirrors {@code ntlm_response}, dispatching to the configured dialect (NTLMv2, NTLM2SR, NT, LM
   * or combined NT+LM).
   *
   * @param challenge the raw bytes of the parent proxy's Type-2 challenge message
   * @param creds the credentials (dialect switches + password hashes)
   */
  @SuppressWarnings({"java:S3776", "java:S135"})
  public static byte[] type3Response(byte[] challenge, Credentials creds) {
    int chalLen = challenge.length;

    // Parse the target-information block (used by NTLMv2).
    int tbofs = 0;
    int tblen = 0;
    int lastType = -1;
    if (chalLen >= NTLM_CHALLENGE_MIN) {
      int tpos = Le.readU16(challenge, 44);
      tbofs = tpos;
      while (tpos + 4 <= chalLen) {
        int ttype = Le.readU16(challenge, tpos);
        lastType = ttype;
        if (ttype == 0) {
          break;
        }
        int tlen = Le.readU16(challenge, tpos + 2);
        if (tpos + 4 + tlen > chalLen) {
          break;
        }
        tpos += 4 + tlen;
        tblen += 4 + tlen;
      }
      if (tblen != 0 && lastType == 0) {
        tblen += 4;
      }
    }

    byte[] ntHash = null;
    byte[] lmHash = null;

    if (creds.getHashNtlm2() != 0) {
      val r = ntlm2CalcResp(creds.getPassNtlm2(), challenge, tbofs, tblen);
      ntHash = r[0];
      lmHash = r[1];
    }
    if (creds.getHashNt() == 2) {
      val r = ntlm2srCalcResp(creds.getPassNt(), challenge);
      ntHash = r[0];
      lmHash = r[1];
    }
    if (creds.getHashNt() == 1) {
      ntHash = ntlmCalcResp(creds.getPassNt(), serverChallenge(challenge));
    }
    if (creds.getHashLm() != 0) {
      lmHash = ntlmCalcResp(creds.getPassLm(), serverChallenge(challenge));
    }

    int ntlen = ntHash == null ? 0 : ntHash.length;
    int lmlen = lmHash == null ? 0 : lmHash.length;

    val unicode = creds.getHashNt() != 0 || creds.getHashNtlm2() != 0;
    final byte[] udomain;
    final byte[] uuser;
    final byte[] uhost;
    if (unicode) {
      udomain = toUnicode(creds.getDomain().toUpperCase());
      uuser = toUnicode(creds.getUser());
      uhost = toUnicode(creds.getWorkstation().toUpperCase());
    } else {
      udomain = toOem(creds.getDomain().toUpperCase());
      uuser = toOem(creds.getUser().toUpperCase());
      uhost = toOem(creds.getWorkstation().toUpperCase());
    }
    int dlen = udomain.length;
    int ulen = uuser.length;
    int hlen = uhost.length;

    val buf = new byte[NTLM_BUFSIZE];
    arraycopy("NTLMSSP\0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), 0, buf, 0, 8);
    Le.u32(buf, 8, 3);

    // LM response security buffer
    Le.u16(buf, 12, lmlen);
    Le.u16(buf, 14, lmlen);
    Le.u32(buf, 16, 64L + dlen + ulen + hlen);

    // NT response security buffer
    Le.u16(buf, 20, ntlen);
    Le.u16(buf, 22, ntlen);
    Le.u32(buf, 24, 64L + dlen + ulen + hlen + lmlen);

    // Domain
    Le.u16(buf, 28, dlen);
    Le.u16(buf, 30, dlen);
    Le.u32(buf, 32, 64);

    // Username
    Le.u16(buf, 36, ulen);
    Le.u16(buf, 38, ulen);
    Le.u32(buf, 40, 64L + dlen);

    // Workstation
    Le.u16(buf, 44, hlen);
    Le.u16(buf, 46, hlen);
    Le.u32(buf, 48, 64L + dlen + ulen);

    // Session key (empty)
    Le.u16(buf, 52, 0);
    Le.u16(buf, 54, 0);
    Le.u16(buf, 56, 64 + dlen + ulen + hlen + lmlen + ntlen);

    // Flags: echo the server's flags from the challenge (bytes 20..24)
    arraycopy(challenge, 20, buf, 60, 4);

    int p = 64;
    arraycopy(udomain, 0, buf, p, dlen);
    arraycopy(uuser, 0, buf, p + dlen, ulen);
    arraycopy(uhost, 0, buf, p + dlen + ulen, hlen);
    if (lmHash != null) {
      arraycopy(lmHash, 0, buf, p + dlen + ulen + hlen, lmlen);
    }
    if (ntHash != null) {
      // Faithful to CNTLM: NT response is placed 24 bytes after the identity fields.
      arraycopy(ntHash, 0, buf, p + dlen + ulen + hlen + 24, ntlen);
    }

    int total = 64 + dlen + ulen + hlen + lmlen + ntlen;
    return Arrays.copyOf(buf, total);
  }

  /** Extracts the 8-byte server challenge (bytes 24..32) from a Type-2 message. */
  private static byte[] serverChallenge(byte[] challenge) {
    return Arrays.copyOfRange(challenge, 24, 32);
  }

  /**
   * Computes a classic 24-byte NTLM/LM response: three DES-ECB encryptions of the 8-byte challenge,
   * keyed by the 16-byte password hash padded to 21 bytes. Ports {@code ntlm_calc_resp}.
   */
  private static byte[] ntlmCalcResp(byte[] hash16, byte[] challenge8) {
    byte[] keys = new byte[21];
    arraycopy(hash16, 0, keys, 0, Math.min(16, hash16.length));
    byte[] out = new byte[24];
    arraycopy(desEncryptBlock(keys, 0, challenge8), 0, out, 0, 8);
    arraycopy(desEncryptBlock(keys, 7, challenge8), 0, out, 8, 8);
    arraycopy(desEncryptBlock(keys, 14, challenge8), 0, out, 16, 8);
    return out;
  }

  /**
   * Computes the NTLMv2 response. Returns {@code [ntResponse, lmResponse]}. Ports {@code
   * ntlm2_calc_resp}.
   */
  private static byte[][] ntlm2CalcResp(byte[] passNtlm2, byte[] challenge, int tbofs, int tblen) {
    val nonce = new byte[8];
    RANDOM.nextBytes(nonce);
    val timestamp = (System.currentTimeMillis() / 1000L + FILETIME_EPOCH_OFFSET) * 10000000L;

    val blen = 28 + tblen + 4;
    val blob = new byte[blen];
    Le.u32(blob, 0, 0x00000101L);
    Le.u32(blob, 4, 0);
    Le.u64(blob, 8, timestamp);
    arraycopy(nonce, 0, blob, 16, 8);
    Le.u32(blob, 24, 0);
    arraycopy(challenge, tbofs, blob, 28, tblen);
    // last 4 bytes remain zero

    val serverChal = serverChallenge(challenge);

    // NT response = HMAC-MD5(passNtlm2, serverChallenge || blob) || blob // NOSONAR java:S125
    val ntProofInput = new byte[8 + blen];
    arraycopy(serverChal, 0, ntProofInput, 0, 8);
    arraycopy(blob, 0, ntProofInput, 8, blen);
    val ntProof = NtlmCrypto.hmacMd5(passNtlm2, ntProofInput);
    val ntResp = new byte[16 + blen];
    arraycopy(ntProof, 0, ntResp, 0, 16);
    arraycopy(blob, 0, ntResp, 16, blen);

    // LMv2 response = HMAC-MD5(passNtlm2, serverChallenge || nonce) || nonce // NOSONAR java:S125
    val lmInput = new byte[16];
    arraycopy(serverChal, 0, lmInput, 0, 8);
    arraycopy(nonce, 0, lmInput, 8, 8);
    val lmResp = new byte[24];
    arraycopy(NtlmCrypto.hmacMd5(passNtlm2, lmInput), 0, lmResp, 0, 16);
    arraycopy(nonce, 0, lmResp, 16, 8);

    return new byte[][] {ntResp, lmResp};
  }

  /**
   * Computes the NTLM2 session response (NTLM2SR). Returns {@code [ntResponse, lmResponse]}. Ports
   * {@code ntlm2sr_calc_rest}.
   */
  private static byte[][] ntlm2srCalcResp(byte[] passNt, byte[] challenge) {
    val nonce = new byte[8];
    RANDOM.nextBytes(nonce);

    val lmResp = new byte[24];
    arraycopy(nonce, 0, lmResp, 0, 8);
    // remaining 16 bytes are zero

    val sessInput = new byte[16];
    arraycopy(serverChallenge(challenge), 0, sessInput, 0, 8);
    arraycopy(nonce, 0, sessInput, 8, 8);
    val sess = NtlmCrypto.md5(sessInput);

    val ntResp = ntlmCalcResp(passNt, Arrays.copyOfRange(sess, 0, 8));
    return new byte[][] {ntResp, lmResp};
  }
}
