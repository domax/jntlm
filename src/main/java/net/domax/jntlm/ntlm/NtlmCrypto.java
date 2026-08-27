package net.domax.jntlm.ntlm;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Low-level cryptographic primitives used by the NTLM protocol.
 *
 * <p>Ports the relevant pieces of CNTLM's {@code ntlm.c} / {@code xcrypt.c}: the 7-to-8 byte
 * DES key-parity expansion ({@code ntlm_set_key}), single-block DES-ECB encryption, MD5,
 * HMAC-MD5 and MD4 (via {@link Md4}). NT/LM responses use DES, NTLMv2 uses HMAC-MD5.
 */
final class NtlmCrypto {

    private NtlmCrypto() {
    }

    /**
     * Expands a 7-byte block into an 8-byte DES key by inserting a bit after every 7 bits.
     * Mirrors CNTLM's {@code ntlm_set_key}. The DES parity bits are ignored by the cipher.
     *
     * @param src    source buffer
     * @param offset offset of the 7 source bytes within {@code src}
     * @return the 8-byte DES key
     */
    static byte[] expandDesKey(byte[] src, int offset) {
        byte[] key = new byte[8];
        int s0 = src[offset] & 0xff;
        int s1 = src[offset + 1] & 0xff;
        int s2 = src[offset + 2] & 0xff;
        int s3 = src[offset + 3] & 0xff;
        int s4 = src[offset + 4] & 0xff;
        int s5 = src[offset + 5] & 0xff;
        int s6 = src[offset + 6] & 0xff;

        key[0] = (byte) s0;
        key[1] = (byte) (((s0 << 7) & 0xff) | (s1 >> 1));
        key[2] = (byte) (((s1 << 6) & 0xff) | (s2 >> 2));
        key[3] = (byte) (((s2 << 5) & 0xff) | (s3 >> 3));
        key[4] = (byte) (((s3 << 4) & 0xff) | (s4 >> 4));
        key[5] = (byte) (((s4 << 3) & 0xff) | (s5 >> 5));
        key[6] = (byte) (((s5 << 2) & 0xff) | (s6 >> 6));
        key[7] = (byte) ((s6 << 1) & 0xff);
        return key;
    }

    /**
     * Encrypts a single 8-byte block with DES-ECB using a key derived from the 7 bytes at
     * {@code keys[keyOffset..keyOffset+6]}.
     *
     * @param keys      buffer holding the 7-byte key material
     * @param keyOffset offset of the key material
     * @param block     the 8-byte plaintext block (typically the NTLM challenge)
     * @return the 8-byte ciphertext
     */
    static byte[] desEncryptBlock(byte[] keys, int keyOffset, byte[] block) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(expandDesKey(keys, keyOffset), "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(block, 0, 8);
        } catch (Exception e) {
            throw new IllegalStateException("DES encryption failed", e);
        }
    }

    static byte[] md4(byte[] input) {
        return Md4.digest(input);
    }

    static byte[] md5(byte[] input) {
        try {
            return java.security.MessageDigest.getInstance("MD5").digest(input);
        } catch (Exception e) {
            throw new IllegalStateException("MD5 unavailable", e);
        }
    }

    static byte[] hmacMd5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-MD5 failed", e);
        }
    }

    /** Encodes a string as UTF-16LE, as required by NTLM Unicode fields. */
    static byte[] toUnicode(String s) {
        return s.getBytes(StandardCharsets.UTF_16LE);
    }

    /** Encodes a string as OEM (US-ASCII/Latin-1) bytes, used by NTLM/LM non-Unicode fields. */
    static byte[] toOem(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }
}
