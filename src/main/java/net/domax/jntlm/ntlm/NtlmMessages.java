package net.domax.jntlm.ntlm;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Builds NTLM Type-1 (negotiate) and Type-3 (authenticate) messages and computes the
 * challenge responses.
 *
 * <p>Direct port of CNTLM's {@code ntlm_request} and {@code ntlm_response} (plus the
 * {@code ntlm_calc_resp}, {@code ntlm2_calc_resp} and {@code ntlm2sr_calc_rest} helpers)
 * from {@code ntlm.c}. All multi-byte fields are little-endian.
 */
public final class NtlmMessages {

    /** Minimum Type-2 challenge length for which a target-info block is parsed. */
    private static final int NTLM_CHALLENGE_MIN = 40;

    private static final int NTLM_BUFSIZE = 1024;

    /** Offset between the Unix epoch and the Windows FILETIME epoch (1601), in seconds. */
    private static final long FILETIME_EPOCH_OFFSET = 11644473600L;

    private static final SecureRandom RANDOM = new SecureRandom();

    private NtlmMessages() {
    }

    /**
     * Builds the NTLM Type-1 (negotiate) message. Mirrors {@code ntlm_request}: the domain and
     * workstation are sent upper-cased in the OEM charset, and the default per-dialect negotiate
     * flags are chosen unless {@code creds.flags} overrides them.
     */
    public static byte[] type1Request(Credentials creds) {
        long flags;
        if (creds.getFlags() != 0) {
            flags = creds.getFlags();
        } else if (creds.getHashNtlm2() != 0) {
            flags = 0xa208b205L;
        } else if (creds.getHashNt() == 2) {
            flags = 0xa208b207L;
        } else if (creds.getHashNt() != 0 && creds.getHashLm() != 0) {
            flags = 0xb207L;
        } else if (creds.getHashNt() != 0) {
            flags = 0xb205L;
        } else if (creds.getHashLm() != 0) {
            flags = 0xb206L;
        } else {
            throw new IllegalStateException("No NTLM hash configured in credentials");
        }

        byte[] domain = NtlmCrypto.toOem(creds.getDomain().toUpperCase());
        byte[] host = NtlmCrypto.toOem(creds.getWorkstation().toUpperCase());
        int dlen = domain.length;
        int hlen = host.length;

        byte[] buf = new byte[32 + dlen + hlen];
        System.arraycopy("NTLMSSP\0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), 0, buf, 0, 8);
        Le.u32(buf, 8, 1);
        Le.u32(buf, 12, flags);
        Le.u16(buf, 16, dlen);
        Le.u16(buf, 18, dlen);
        Le.u32(buf, 20, 32 + hlen);
        Le.u16(buf, 24, hlen);
        Le.u16(buf, 26, hlen);
        Le.u32(buf, 28, 32);
        System.arraycopy(host, 0, buf, 32, hlen);
        System.arraycopy(domain, 0, buf, 32 + hlen, dlen);
        return buf;
    }

    /**
     * Builds the NTLM Type-3 (authenticate) message in response to the given Type-2 challenge.
     * Mirrors {@code ntlm_response}, dispatching to the configured dialect (NTLMv2, NTLM2SR,
     * NT, LM or combined NT+LM).
     *
     * @param challenge the raw bytes of the parent proxy's Type-2 challenge message
     * @param creds     the credentials (dialect switches + password hashes)
     */
    public static byte[] type3Response(byte[] challenge, Credentials creds) {
        int challen = challenge.length;

        // Parse the target-information block (used by NTLMv2).
        int tbofs = 0;
        int tblen = 0;
        int lastType = -1;
        if (challen >= NTLM_CHALLENGE_MIN) {
            int tpos = Le.readU16(challenge, 44);
            tbofs = tpos;
            while (tpos + 4 <= challen) {
                int ttype = Le.readU16(challenge, tpos);
                lastType = ttype;
                if (ttype == 0) {
                    break;
                }
                int tlen = Le.readU16(challenge, tpos + 2);
                if (tpos + 4 + tlen > challen) {
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
            byte[][] r = ntlm2CalcResp(creds.getPassNtlm2(), challenge, tbofs, tblen);
            ntHash = r[0];
            lmHash = r[1];
        }
        if (creds.getHashNt() == 2) {
            byte[][] r = ntlm2srCalcResp(creds.getPassNt(), challenge);
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

        boolean unicode = creds.getHashNt() != 0 || creds.getHashNtlm2() != 0;
        byte[] udomain;
        byte[] uuser;
        byte[] uhost;
        if (unicode) {
            udomain = NtlmCrypto.toUnicode(creds.getDomain().toUpperCase());
            uuser = NtlmCrypto.toUnicode(creds.getUser());
            uhost = NtlmCrypto.toUnicode(creds.getWorkstation().toUpperCase());
        } else {
            udomain = NtlmCrypto.toOem(creds.getDomain().toUpperCase());
            uuser = NtlmCrypto.toOem(creds.getUser().toUpperCase());
            uhost = NtlmCrypto.toOem(creds.getWorkstation().toUpperCase());
        }
        int dlen = udomain.length;
        int ulen = uuser.length;
        int hlen = uhost.length;

        byte[] buf = new byte[NTLM_BUFSIZE];
        System.arraycopy("NTLMSSP\0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), 0, buf, 0, 8);
        Le.u32(buf, 8, 3);

        // LM response security buffer
        Le.u16(buf, 12, lmlen);
        Le.u16(buf, 14, lmlen);
        Le.u32(buf, 16, 64 + dlen + ulen + hlen);

        // NT response security buffer
        Le.u16(buf, 20, ntlen);
        Le.u16(buf, 22, ntlen);
        Le.u32(buf, 24, 64 + dlen + ulen + hlen + lmlen);

        // Domain
        Le.u16(buf, 28, dlen);
        Le.u16(buf, 30, dlen);
        Le.u32(buf, 32, 64);

        // Username
        Le.u16(buf, 36, ulen);
        Le.u16(buf, 38, ulen);
        Le.u32(buf, 40, 64 + dlen);

        // Workstation
        Le.u16(buf, 44, hlen);
        Le.u16(buf, 46, hlen);
        Le.u32(buf, 48, 64 + dlen + ulen);

        // Session key (empty)
        Le.u16(buf, 52, 0);
        Le.u16(buf, 54, 0);
        Le.u16(buf, 56, 64 + dlen + ulen + hlen + lmlen + ntlen);

        // Flags: echo the server's flags from the challenge (bytes 20..24)
        System.arraycopy(challenge, 20, buf, 60, 4);

        int p = 64;
        System.arraycopy(udomain, 0, buf, p, dlen);
        System.arraycopy(uuser, 0, buf, p + dlen, ulen);
        System.arraycopy(uhost, 0, buf, p + dlen + ulen, hlen);
        if (lmHash != null) {
            System.arraycopy(lmHash, 0, buf, p + dlen + ulen + hlen, lmlen);
        }
        if (ntHash != null) {
            // Faithful to CNTLM: NT response is placed 24 bytes after the identity fields.
            System.arraycopy(ntHash, 0, buf, p + dlen + ulen + hlen + 24, ntlen);
        }

        int total = 64 + dlen + ulen + hlen + lmlen + ntlen;
        return Arrays.copyOf(buf, total);
    }

    /** Extracts the 8-byte server challenge (bytes 24..32) from a Type-2 message. */
    private static byte[] serverChallenge(byte[] challenge) {
        return Arrays.copyOfRange(challenge, 24, 32);
    }

    /**
     * Computes a classic 24-byte NTLM/LM response: three DES-ECB encryptions of the 8-byte
     * challenge, keyed by the 16-byte password hash padded to 21 bytes. Ports {@code ntlm_calc_resp}.
     */
    private static byte[] ntlmCalcResp(byte[] hash16, byte[] challenge8) {
        byte[] keys = new byte[21];
        System.arraycopy(hash16, 0, keys, 0, Math.min(16, hash16.length));
        byte[] out = new byte[24];
        System.arraycopy(NtlmCrypto.desEncryptBlock(keys, 0, challenge8), 0, out, 0, 8);
        System.arraycopy(NtlmCrypto.desEncryptBlock(keys, 7, challenge8), 0, out, 8, 8);
        System.arraycopy(NtlmCrypto.desEncryptBlock(keys, 14, challenge8), 0, out, 16, 8);
        return out;
    }

    /**
     * Computes the NTLMv2 response. Returns {@code [ntResponse, lmResponse]}.
     * Ports {@code ntlm2_calc_resp}.
     */
    private static byte[][] ntlm2CalcResp(byte[] passNtlm2, byte[] challenge, int tbofs, int tblen) {
        byte[] nonce = new byte[8];
        RANDOM.nextBytes(nonce);
        long timestamp = (System.currentTimeMillis() / 1000L + FILETIME_EPOCH_OFFSET) * 10000000L;

        int blen = 28 + tblen + 4;
        byte[] blob = new byte[blen];
        Le.u32(blob, 0, 0x00000101L);
        Le.u32(blob, 4, 0);
        Le.u64(blob, 8, timestamp);
        System.arraycopy(nonce, 0, blob, 16, 8);
        Le.u32(blob, 24, 0);
        System.arraycopy(challenge, tbofs, blob, 28, tblen);
        // last 4 bytes remain zero

        byte[] serverChal = serverChallenge(challenge);

        // NT response = HMAC-MD5(passNtlm2, serverChallenge || blob) || blob
        byte[] ntProofInput = new byte[8 + blen];
        System.arraycopy(serverChal, 0, ntProofInput, 0, 8);
        System.arraycopy(blob, 0, ntProofInput, 8, blen);
        byte[] ntProof = NtlmCrypto.hmacMd5(passNtlm2, ntProofInput);
        byte[] ntResp = new byte[16 + blen];
        System.arraycopy(ntProof, 0, ntResp, 0, 16);
        System.arraycopy(blob, 0, ntResp, 16, blen);

        // LMv2 response = HMAC-MD5(passNtlm2, serverChallenge || nonce) || nonce
        byte[] lmInput = new byte[16];
        System.arraycopy(serverChal, 0, lmInput, 0, 8);
        System.arraycopy(nonce, 0, lmInput, 8, 8);
        byte[] lmResp = new byte[24];
        System.arraycopy(NtlmCrypto.hmacMd5(passNtlm2, lmInput), 0, lmResp, 0, 16);
        System.arraycopy(nonce, 0, lmResp, 16, 8);

        return new byte[][] {ntResp, lmResp};
    }

    /**
     * Computes the NTLM2 session response (NTLM2SR). Returns {@code [ntResponse, lmResponse]}.
     * Ports {@code ntlm2sr_calc_rest}.
     */
    private static byte[][] ntlm2srCalcResp(byte[] passNt, byte[] challenge) {
        byte[] nonce = new byte[8];
        RANDOM.nextBytes(nonce);

        byte[] lmResp = new byte[24];
        System.arraycopy(nonce, 0, lmResp, 0, 8);
        // remaining 16 bytes are zero

        byte[] sessInput = new byte[16];
        System.arraycopy(serverChallenge(challenge), 0, sessInput, 0, 8);
        System.arraycopy(nonce, 0, sessInput, 8, 8);
        byte[] sess = NtlmCrypto.md5(sessInput);

        byte[] ntResp = ntlmCalcResp(passNt, Arrays.copyOfRange(sess, 0, 8));
        return new byte[][] {ntResp, lmResp};
    }
}
