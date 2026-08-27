package net.domax.jntlm.config;

import net.domax.jntlm.ntlm.Credentials;

/**
 * NTLM authentication dialect, mirroring CNTLM's {@code Auth} option.
 *
 * <p>Each mode maps to the {@code hashNt}/{@code hashLm}/{@code hashNtlm2} switches on
 * {@link Credentials} exactly as CNTLM does in {@code main.c} (the {@code magic_auth_detect}
 * / {@code Auth} parsing section).
 */
public enum AuthMode {

    /** NTLMv2 — the secure default. */
    NTLMV2(0, 0, 1),
    /** NTLM2 session response. */
    NTLM2SR(2, 0, 0),
    /** NT response only. */
    NT(1, 0, 0),
    /** Combined NT + LM response. */
    NTLM(1, 1, 0),
    /** LM response only (weakest). */
    LM(0, 1, 0);

    private final int hashNt;
    private final int hashLm;
    private final int hashNtlm2;

    AuthMode(int hashNt, int hashLm, int hashNtlm2) {
        this.hashNt = hashNt;
        this.hashLm = hashLm;
        this.hashNtlm2 = hashNtlm2;
    }

    /** Applies this dialect's hash switches onto the given credentials. */
    public void applyTo(Credentials creds) {
        creds.setHashNt(hashNt);
        creds.setHashLm(hashLm);
        creds.setHashNtlm2(hashNtlm2);
    }
}
