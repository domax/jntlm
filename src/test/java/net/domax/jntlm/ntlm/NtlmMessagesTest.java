package net.domax.jntlm.ntlm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

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
        Le.u32(challenge, 20, 0x00000200);          // flags (echoed into Type-3)
        for (int i = 0; i < 8; i++) {
            challenge[24 + i] = (byte) (0x11 * (i + 1)); // server challenge
        }
        Le.u16(challenge, 44, 48);                   // target-info offset
        Le.u16(challenge, 48, 0);                    // AV pair: MsvAvEOL (type 0, len 0)
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
        byte[] expected = {0x12, 0x1a, 0x15, (byte) 0xcf, (byte) 0x89, (byte) 0xd5, (byte) 0xf3,
                (byte) 0xbc};
        assertArrayEquals(expected, key);
    }
}
