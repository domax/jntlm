/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import net.domax.jntlm.config.AuthMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Structural tests for the NTLM Type-1 and Type-3 messages and DES key expansion. */
class NtlmMessagesTest {

  private static final byte[] SIGNATURE = "NTLMSSP\0".getBytes(StandardCharsets.ISO_8859_1);

  private static void assertSignature(byte[] msg) {
    for (int i = 0; i < 8; i++) {
      assertEquals(SIGNATURE[i], msg[i], "signature byte " + i);
    }
  }

  private static Credentials ntlmCreds() {
    Credentials c = new Credentials();
    c.setUser("testuser");
    c.setDomain("TESTDOMAIN");
    c.setWorkstation("WS");
    c.setHashNt(1);
    c.setHashLm(1);
    c.setPassNt(NtlmHashes.ntHash("SecREt01"));
    c.setPassLm(NtlmHashes.lmHash("SecREt01"));
    return c;
  }

  static final byte[] GOLDEN_NONCE = {1, 2, 3, 4, 5, 6, 7, 8};
  static final long GOLDEN_MILLIS = 1_700_000_000_000L;

  /** Type-2 challenge (68 bytes) whose target info holds a domain AV pair and MsvAvEOL. */
  static byte[] goldenChallenge() {
    byte[] c = new byte[68];
    System.arraycopy(SIGNATURE, 0, c, 0, 8);
    Le.u32(c, 8, 2);
    Le.u32(c, 20, 0xa2898205L);
    for (int i = 0; i < 8; i++) c[24 + i] = (byte) (0x11 * (i + 1));
    Le.u16(c, 40, 20);
    Le.u16(c, 42, 20);
    Le.u32(c, 44, 48);
    Le.u16(c, 48, 2);
    Le.u16(c, 50, 12);
    System.arraycopy("D\0O\0M\0A\0I\0N\0".getBytes(StandardCharsets.ISO_8859_1), 0, c, 52, 12);
    Le.u16(c, 64, 0);
    Le.u16(c, 66, 0);
    return c;
  }

  static Credentials goldenCreds(AuthMode mode) {
    Credentials c = new Credentials();
    c.setUser("testuser");
    c.setDomain("TESTDOMAIN");
    c.setWorkstation("WS");
    c.setPassNt(NtlmHashes.ntHash("SecREt01"));
    c.setPassLm(NtlmHashes.lmHash("SecREt01"));
    c.setPassNtlm2(NtlmHashes.ntlm2Hash("testuser", "TESTDOMAIN", "SecREt01"));
    return mode.applyTo(c);
  }

  /**
   * Type-3 bytes captured before the exact-size allocation change; must stay byte-identical
   * (including CNTLM's quirk of writing the NT response 24 bytes after the identity fields).
   */
  private static final Map<AuthMode, String> GOLDEN_TYPE3 =
      Map.ofEntries(
          Map.entry(
              AuthMode.NTLMV2,
              "4e544c4d53535000030000001800180068000000440044008000000014001400"
                  + "400000001000100054000000040004006400000000000000c4000000058289a2"
                  + "540045005300540044004f004d00410049004e00740065007300740075007300"
                  + "6500720057005300cfe862a6f2261aa6b2e30987daf96ea70102030405060708"
                  + "159a5378cda3e7964bb7b04b88c1d2bc010100000000000000006dc64717da01"
                  + "01020304050607080000000002000c0044004f004d00410049004e0000000000"
                  + "00000000"),
          Map.entry(
              AuthMode.NTLM2SR,
              "4e544c4d53535000030000001800180068000000180018008000000014001400"
                  + "40000000100010005400000004000400640000000000000098000000058289a2"
                  + "540045005300540044004f004d00410049004e00740065007300740075007300"
                  + "6500720057005300010203040506070800000000000000000000000000000000"
                  + "3a3a0dcd2a130ef519dbe1fb7b9644ab7737323578e09602"),
          Map.entry(
              AuthMode.NT,
              "4e544c4d53535000030000000000000068000000180018006800000014001400"
                  + "40000000100010005400000004000400640000000000000080000000058289a2"
                  + "540045005300540044004f004d00410049004e00740065007300740075007300"
                  + "6500720057005300000000000000000000000000000000000000000000000000"),
          Map.entry(
              AuthMode.NTLM,
              "4e544c4d53535000030000001800180068000000180018008000000014001400"
                  + "40000000100010005400000004000400640000000000000098000000058289a2"
                  + "540045005300540044004f004d00410049004e00740065007300740075007300"
                  + "650072005700530085800bdf6cf94e239a191309aabfbdefe0a197ecb09473ec"
                  + "2d750d2596edf9b6db6598f42df6d9bcd9c14afe809647e1"),
          Map.entry(
              AuthMode.LM,
              "4e544c4d53535000030000001800180054000000000000006c0000000a000a00"
                  + "40000000080008004a0000000200020052000000000000006c000000058289a2"
                  + "54455354444f4d41494e5445535455534552575385800bdf6cf94e239a191309"
                  + "aabfbdefe0a197ecb09473ec"));

  @ParameterizedTest
  @EnumSource(AuthMode.class)
  void type3MatchesGoldenVector(AuthMode mode) {
    byte[] msg =
        NtlmMessages.type3Response(
            goldenChallenge(), goldenCreds(mode), GOLDEN_NONCE, GOLDEN_MILLIS);
    assertEquals(GOLDEN_TYPE3.get(mode), HexFormat.of().formatHex(msg));
  }

  private static byte[] challenge(int len) {
    byte[] c = new byte[len];
    System.arraycopy(SIGNATURE, 0, c, 0, 8);
    Le.u32(c, 8, 2);
    Le.u32(c, 20, 0xa2898205L);
    return c;
  }

  /** NT response length announced in the Type-3 security buffer at offset 20. */
  private static int ntLen(byte[] type3) {
    return Le.readU16(type3, 20);
  }

  @Test
  void shortChallengeBuildsType3WithoutTargetInfo() {
    byte[] msg = NtlmMessages.type3Response(challenge(44), goldenCreds(AuthMode.NTLMV2));
    assertEquals(3, msg[8] & 0xff);
    assertEquals(16 + 28 + 4, ntLen(msg));
  }

  @Test
  void wrongSignatureIsRejected() {
    byte[] c = challenge(64);
    c[0] = 'X';
    assertThrows(NtlmException.class, () -> NtlmMessages.type3Response(c, ntlmCreds()));
  }

  @Test
  void wrongTypeOrTooShortIsRejected() {
    byte[] type1 = challenge(64);
    Le.u32(type1, 8, 1);
    assertThrows(NtlmException.class, () -> NtlmMessages.type3Response(type1, ntlmCreds()));
    assertThrows(NtlmException.class, () -> NtlmMessages.type3Response(challenge(31), ntlmCreds()));
    assertThrows(NtlmException.class, () -> NtlmMessages.type3Response(new byte[0], ntlmCreds()));
  }

  @Test
  void targetInfoOffsetOutsideMessageIsIgnored() {
    byte[] c = challenge(64);
    Le.u16(c, 40, 8);
    Le.u16(c, 42, 8);
    Le.u32(c, 44, 1000);
    byte[] msg = NtlmMessages.type3Response(c, goldenCreds(AuthMode.NTLMV2));
    assertEquals(16 + 28 + 4, ntLen(msg));
  }

  @Test
  void largeTargetInfoIsCarriedInFull() {
    byte[] c = challenge(48 + 2000);
    Le.u16(c, 40, 2000);
    Le.u16(c, 42, 2000);
    Le.u32(c, 44, 48);
    Le.u16(c, 48, 2);
    Le.u16(c, 50, 1992);
    for (int i = 0; i < 1992; i++) c[52 + i] = (byte) i;
    // trailing MsvAvEOL (4 zero bytes) at 2044..2048

    byte[] msg = NtlmMessages.type3Response(c, goldenCreds(AuthMode.NTLMV2));
    int nt = ntLen(msg);
    assertEquals(16 + 28 + 2000 + 4, nt);
    int ntOfs = Le.readU16(msg, 24);
    assertEquals(msg.length, ntOfs + nt, "Type-3 must be sized to its content");
    assertArrayEquals(
        Arrays.copyOfRange(c, 48, 2048),
        Arrays.copyOfRange(msg, ntOfs + 16 + 28, ntOfs + 16 + 28 + 2000));
  }

  @Test
  void oversizedFieldIsRejected() {
    Credentials creds = ntlmCreds();
    creds.setUser("u".repeat(40_000));
    assertThrows(
        NtlmException.class,
        () -> NtlmMessages.type3Response(goldenChallenge(), creds),
        "unicode user of 80000 bytes cannot fit a 16-bit length");
  }

  @Test
  void type1HasSignatureAndType() {
    byte[] msg = NtlmMessages.type1Request(ntlmCreds());
    assertSignature(msg);
    assertEquals(1, msg[8] & 0xff, "message type must be 1");
  }

  @Test
  void type3HasSignatureAndType() {
    // Minimal, well-formed Type-2 challenge (52 bytes) with an empty target-info block.
    byte[] challenge = new byte[52];
    System.arraycopy(SIGNATURE, 0, challenge, 0, 8);
    Le.u32(challenge, 8, 2);
    Le.u32(challenge, 20, 0x00000200); // flags (echoed into Type-3)
    for (int i = 0; i < 8; i++) {
      challenge[24 + i] = (byte) (0x11 * (i + 1)); // server challenge
    }
    Le.u16(challenge, 44, 48); // target-info offset
    Le.u16(challenge, 48, 0); // AV pair: MsvAvEOL (type 0, len 0)
    Le.u16(challenge, 50, 0);

    byte[] msg = NtlmMessages.type3Response(challenge, ntlmCreds());
    assertSignature(msg);
    assertEquals(3, msg[8] & 0xff, "message type must be 3");
    assertTrue(msg.length > 64, "Type-3 must carry identity + response fields");
  }

  @Test
  void desKeyExpansionSpreadsSevenBytesIntoEight() {
    // Ports CNTLM's ntlm_set_key: 7 key bytes are spread across 8 (7-bit shifts), the low
    // parity bit is left unset (DES ignores it). Exact known-answer for a fixed input.
    byte[] src = {0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde};
    byte[] key = NtlmCrypto.expandDesKey(src, 0);
    byte[] expected = {
      0x12, 0x1a, 0x15, (byte) 0xcf, (byte) 0x89, (byte) 0xd5, (byte) 0xf3, (byte) 0xbc
    };
    assertArrayEquals(expected, key);
  }
}
