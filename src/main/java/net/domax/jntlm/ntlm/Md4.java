package net.domax.jntlm.ntlm;

/**
 * Pure-Java implementation of the MD4 message digest (RFC 1320).
 *
 * <p>MD4 is required to compute the NT password hash but is not provided by the standard
 * Java Cryptography Architecture, so it is implemented here. Ported to mirror the behaviour
 * relied upon by CNTLM's {@code md4_buffer} (via {@code ntlm_hash_nt_password}).
 */
final class Md4 {

    private Md4() {
    }

    /** Computes the 16-byte MD4 digest of {@code input}. */
    static byte[] digest(byte[] input) {
        int a = 0x67452301;
        int b = 0xefcdab89;
        int c = 0x98badcfe;
        int d = 0x10325476;

        // Pad the message: append 0x80, then zeros, then the 64-bit little-endian bit length.
        long bitLen = (long) input.length * 8;
        int paddedLen = ((input.length + 8) / 64 + 1) * 64;
        byte[] msg = new byte[paddedLen];
        System.arraycopy(input, 0, msg, 0, input.length);
        msg[input.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            msg[paddedLen - 8 + i] = (byte) (bitLen >>> (8 * i));
        }

        int[] x = new int[16];
        for (int off = 0; off < paddedLen; off += 64) {
            for (int i = 0; i < 16; i++) {
                x[i] = (msg[off + i * 4] & 0xff)
                        | ((msg[off + i * 4 + 1] & 0xff) << 8)
                        | ((msg[off + i * 4 + 2] & 0xff) << 16)
                        | ((msg[off + i * 4 + 3] & 0xff) << 24);
            }

            int aa = a;
            int bb = b;
            int cc = c;
            int dd = d;

            // Round 1
            a = ff(a, b, c, d, x[0], 3);
            d = ff(d, a, b, c, x[1], 7);
            c = ff(c, d, a, b, x[2], 11);
            b = ff(b, c, d, a, x[3], 19);
            a = ff(a, b, c, d, x[4], 3);
            d = ff(d, a, b, c, x[5], 7);
            c = ff(c, d, a, b, x[6], 11);
            b = ff(b, c, d, a, x[7], 19);
            a = ff(a, b, c, d, x[8], 3);
            d = ff(d, a, b, c, x[9], 7);
            c = ff(c, d, a, b, x[10], 11);
            b = ff(b, c, d, a, x[11], 19);
            a = ff(a, b, c, d, x[12], 3);
            d = ff(d, a, b, c, x[13], 7);
            c = ff(c, d, a, b, x[14], 11);
            b = ff(b, c, d, a, x[15], 19);

            // Round 2
            a = gg(a, b, c, d, x[0], 3);
            d = gg(d, a, b, c, x[4], 5);
            c = gg(c, d, a, b, x[8], 9);
            b = gg(b, c, d, a, x[12], 13);
            a = gg(a, b, c, d, x[1], 3);
            d = gg(d, a, b, c, x[5], 5);
            c = gg(c, d, a, b, x[9], 9);
            b = gg(b, c, d, a, x[13], 13);
            a = gg(a, b, c, d, x[2], 3);
            d = gg(d, a, b, c, x[6], 5);
            c = gg(c, d, a, b, x[10], 9);
            b = gg(b, c, d, a, x[14], 13);
            a = gg(a, b, c, d, x[3], 3);
            d = gg(d, a, b, c, x[7], 5);
            c = gg(c, d, a, b, x[11], 9);
            b = gg(b, c, d, a, x[15], 13);

            // Round 3
            a = hh(a, b, c, d, x[0], 3);
            d = hh(d, a, b, c, x[8], 9);
            c = hh(c, d, a, b, x[4], 11);
            b = hh(b, c, d, a, x[12], 15);
            a = hh(a, b, c, d, x[2], 3);
            d = hh(d, a, b, c, x[10], 9);
            c = hh(c, d, a, b, x[6], 11);
            b = hh(b, c, d, a, x[14], 15);
            a = hh(a, b, c, d, x[1], 3);
            d = hh(d, a, b, c, x[9], 9);
            c = hh(c, d, a, b, x[5], 11);
            b = hh(b, c, d, a, x[13], 15);
            a = hh(a, b, c, d, x[3], 3);
            d = hh(d, a, b, c, x[11], 9);
            c = hh(c, d, a, b, x[7], 11);
            b = hh(b, c, d, a, x[15], 15);

            a += aa;
            b += bb;
            c += cc;
            d += dd;
        }

        byte[] out = new byte[16];
        writeLe(out, 0, a);
        writeLe(out, 4, b);
        writeLe(out, 8, c);
        writeLe(out, 12, d);
        return out;
    }

    private static int ff(int a, int b, int c, int d, int x, int s) {
        a += ((b & c) | (~b & d)) + x;
        return Integer.rotateLeft(a, s);
    }

    private static int gg(int a, int b, int c, int d, int x, int s) {
        a += ((b & c) | (b & d) | (c & d)) + x + 0x5a827999;
        return Integer.rotateLeft(a, s);
    }

    private static int hh(int a, int b, int c, int d, int x, int s) {
        a += (b ^ c ^ d) + x + 0x6ed9eba1;
        return Integer.rotateLeft(a, s);
    }

    private static void writeLe(byte[] out, int off, int val) {
        out[off] = (byte) val;
        out[off + 1] = (byte) (val >>> 8);
        out[off + 2] = (byte) (val >>> 16);
        out[off + 3] = (byte) (val >>> 24);
    }
}
