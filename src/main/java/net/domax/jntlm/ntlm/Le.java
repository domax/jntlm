/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

/** Little-endian read/write helpers for building and parsing NTLM messages. */
final class Le {

  private Le() {}

  static void u16(byte[] buf, int off, int val) {
    buf[off] = (byte) val;
    buf[off + 1] = (byte) (val >>> 8);
  }

  static void u32(byte[] buf, int off, long val) {
    buf[off] = (byte) val;
    buf[off + 1] = (byte) (val >>> 8);
    buf[off + 2] = (byte) (val >>> 16);
    buf[off + 3] = (byte) (val >>> 24);
  }

  @SuppressWarnings("SameParameterValue")
  static void u64(byte[] buf, int off, long val) {
    for (int i = 0; i < 8; ++i) {
      buf[off + i] = (byte) (val >>> (8 * i));
    }
  }

  static int readU16(byte[] buf, int off) {
    return (buf[off] & 0xff) | ((buf[off + 1] & 0xff) << 8);
  }
}
