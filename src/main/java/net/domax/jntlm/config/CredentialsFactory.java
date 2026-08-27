package net.domax.jntlm.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import net.domax.jntlm.ntlm.Credentials;
import net.domax.jntlm.ntlm.NtlmHashes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Builds the global NTLM {@link Credentials} bean from {@link JntlmProperties}.
 *
 * <p>Ports the credential-preparation logic from CNTLM's {@code main.c}: {@code user@domain}
 * splitting, defaulting the workstation to the local hostname, deriving the LM/NT/NTLMv2
 * hashes from a plaintext password, or accepting pre-computed hex hashes.
 */
@Configuration
public class CredentialsFactory {

    @Bean
    public Credentials globalCredentials(JntlmProperties properties) {
        JntlmProperties.Credentials src = properties.getCredentials();
        Credentials creds = new Credentials();

        String user = src.getUsername() == null ? "" : src.getUsername();
        String domain = src.getDomain() == null ? "" : src.getDomain();

        // Split "user@domain" - the domain part overrides the Domain setting.
        int at = user.indexOf('@');
        if (at >= 0) {
            domain = user.substring(at + 1);
            user = user.substring(0, at);
        }
        creds.setUser(user);
        creds.setDomain(domain);

        String workstation = src.getWorkstation();
        if (workstation == null || workstation.isBlank()) {
            workstation = defaultWorkstation();
        }
        creds.setWorkstation(workstation);

        // Select the dialect (sets hashNt/hashLm/hashNtlm2) and optional manual flags.
        properties.getAuth().applyTo(creds);
        creds.setFlags(properties.getFlags());

        String password = src.getPassword();
        if (password != null && !password.isEmpty()) {
            // Derive every hash the configured dialect might need from the plaintext password.
            creds.setPassLm(NtlmHashes.lmHash(password));
            creds.setPassNt(NtlmHashes.ntHash(password));
            creds.setPassNtlm2(NtlmHashes.ntlm2Hash(user, domain, password));
        } else {
            creds.setPassLm(parseHash(src.getPassLm()));
            creds.setPassNt(parseHash(src.getPassNt()));
            creds.setPassNtlm2(parseHash(src.getPassNtlm2()));
        }

        return creds;
    }

    private static String defaultWorkstation() {
        try {
            String host = InetAddress.getLocalHost().getHostName();
            if (host != null && !host.isBlank()) {
                // Use the short NetBIOS-style name (strip the DNS domain suffix).
                int dot = host.indexOf('.');
                return dot > 0 ? host.substring(0, dot) : host;
            }
        } catch (UnknownHostException ignored) {
            // fall through
        }
        return "cntlm";
    }

    /** Parses a 32-char hex string into a 16-byte hash, or returns {@code null} if blank. */
    private static byte[] parseHash(String hex) {
        if (hex == null) {
            return null;
        }
        String h = hex.trim();
        if (h.isEmpty()) {
            return null;
        }
        if (h.length() % 2 != 0) {
            throw new IllegalArgumentException("Hash hex string must have an even length: " + hex);
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
