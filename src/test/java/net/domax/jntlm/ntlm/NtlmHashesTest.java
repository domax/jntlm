package net.domax.jntlm.ntlm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Known-answer tests for the NTLM password hashes against published MS-NLMP vectors. */
class NtlmHashesTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    void ntHashEmptyPassword() {
        assertArrayEquals(hex("31D6CFE0D16AE931B73C59D7E0C089C0"), NtlmHashes.ntHash(""));
    }

    @Test
    void ntHashSecret01() {
        assertArrayEquals(hex("CD06CA7C7E10C99B1D33B7485A2ED808"), NtlmHashes.ntHash("SecREt01"));
    }

    @Test
    void lmHashEmptyPassword() {
        assertArrayEquals(hex("AAD3B435B51404EEAAD3B435B51404EE"), NtlmHashes.lmHash(""));
    }

    @Test
    void lmHashSecret01() {
        assertArrayEquals(hex("FF3750BCC2B22412C2265B23734E0DAC"), NtlmHashes.lmHash("SecREt01"));
    }

    @Test
    void lmHashIsCaseInsensitive() {
        assertArrayEquals(NtlmHashes.lmHash("SECRET01"), NtlmHashes.lmHash("secret01"));
    }

    @Test
    void ntlm2HashLength() {
        // NTLMv2 hash is HMAC-MD5 output: 16 bytes.
        assertEquals(16, NtlmHashes.ntlm2Hash("user", "DOMAIN", "SecREt01").length);
    }
}
