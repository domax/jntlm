/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.ntlm;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import net.domax.jntlm.config.AuthMode;
import org.junit.jupiter.api.Test;

/** Tests for {@link NtlmFlags}. */
class NtlmFlagsTest {

  private static Credentials creds(AuthMode mode) {
    return mode.applyTo(new Credentials());
  }

  @Test
  void defaultsPerDialect() {
    assertEquals(0xa208b205L, NtlmFlags.defaultFor(creds(AuthMode.NTLMV2)));
    assertEquals(0xa208b207L, NtlmFlags.defaultFor(creds(AuthMode.NTLM2SR)));
    assertEquals(0xb205L, NtlmFlags.defaultFor(creds(AuthMode.NT)));
    assertEquals(0xb207L, NtlmFlags.defaultFor(creds(AuthMode.NTLM)));
    assertEquals(0xb206L, NtlmFlags.defaultFor(creds(AuthMode.LM)));
  }

  @Test
  void defaultIgnoresExplicitOverride() {
    assertEquals(0xa208b205L, NtlmFlags.defaultFor(creds(AuthMode.NTLMV2).setFlags(0x205)));
  }

  @Test
  void readsFlagsFromChallenge() {
    byte[] type2 = new byte[48];
    Le.u32(type2, 20, 0xa2088205L);
    assertEquals(0xa2088205L, NtlmFlags.fromChallenge(type2));
    assertEquals(0, NtlmFlags.fromChallenge(new byte[10]));
  }

  @Test
  void formatsHex() {
    assertEquals("0x00088205", NtlmFlags.hex(0x00088205L));
    assertEquals("0xa208b205", NtlmFlags.hex(0xa208b205L));
  }

  @Test
  void ntlmv2Candidates() {
    assertEquals(
        List.of(0xa208b205L, 0x0008b205L, 0x00088205L, 0x00080205L, 0x00000205L),
        NtlmFlags.candidates(creds(AuthMode.NTLMV2), 0));
  }

  @Test
  void explicitCandidateFirstAndNotRepeated() {
    assertEquals(
        List.of(0x00088205L, 0xa208b205L, 0x0008b205L, 0x00080205L, 0x00000205L),
        NtlmFlags.candidates(creds(AuthMode.NTLMV2), 0x00088205L));
  }

  @Test
  void ntCandidates() {
    assertEquals(List.of(0xb205L, 0x8205L, 0x0205L), NtlmFlags.candidates(creds(AuthMode.NT), 0));
  }

  @Test
  void refineUsesServerFlags() {
    Credentials c = creds(AuthMode.NTLMV2);
    assertEquals(0x00088205L, NtlmFlags.refine(0xa208b205L, 0x00088205L, c));
  }

  @Test
  void refineRejectsWithoutNtlmBit() {
    assertEquals(0, NtlmFlags.refine(0xa208b205L, 0x00088005L, creds(AuthMode.NTLMV2)));
  }

  @Test
  void refineRejectsLostCharset() {
    assertEquals(0, NtlmFlags.refine(0xa208b205L, 0x00088204L, creds(AuthMode.NTLMV2)));
  }

  @Test
  void refineRejectsZero() {
    assertEquals(0, NtlmFlags.refine(0x205L, 0x10000000L, creds(AuthMode.NTLMV2)));
  }
}
