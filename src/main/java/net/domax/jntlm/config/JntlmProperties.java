package net.domax.jntlm.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for jntlm, bound from the {@code jntlm.*} properties.
 *
 * <p>Replaces CNTLM's {@code cntlm.conf} options relevant to the core proxy: listen address,
 * NTLM credentials, authentication dialect and the list of parent proxies.
 */
@ConfigurationProperties(prefix = "jntlm")
public class JntlmProperties {

    /** Local address to bind the proxy listener to. Default loopback only. */
    private String listenAddress = "127.0.0.1";

    /** Local TCP port the proxy listens on. */
    private int listenPort = 3128;

    /** NTLM authentication dialect used towards the parent proxy. */
    private AuthMode auth = AuthMode.NTLMV2;

    /** Optional manual NTLM negotiate-flags override (0 = use built-in per-dialect default). */
    private long flags;

    /** Ordered list of parent proxies ({@code host:port}) tried with failover. */
    private List<String> parents = new ArrayList<>();

    private final Credentials credentials = new Credentials();

    public String getListenAddress() {
        return listenAddress;
    }

    public void setListenAddress(String listenAddress) {
        this.listenAddress = listenAddress;
    }

    public int getListenPort() {
        return listenPort;
    }

    public void setListenPort(int listenPort) {
        this.listenPort = listenPort;
    }

    public AuthMode getAuth() {
        return auth;
    }

    public void setAuth(AuthMode auth) {
        this.auth = auth;
    }

    public long getFlags() {
        return flags;
    }

    public void setFlags(long flags) {
        this.flags = flags;
    }

    public List<String> getParents() {
        return parents;
    }

    public void setParents(List<String> parents) {
        this.parents = parents;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    /**
     * Raw credential settings bound from {@code jntlm.credentials.*}. Either a plaintext
     * {@code password} or the pre-computed hex hashes may be supplied.
     */
    public static class Credentials {

        /** Proxy account username (could be given as {@code user@domain}). */
        private String username = "";

        /** NT domain / workgroup. */
        private String domain = "";

        /** NetBIOS workstation name; defaults to the local hostname when blank. */
        private String workstation = "";

        /** Plaintext password (optional if hashes are supplied). */
        private String password = "";

        /** Pre-computed LM hash as a 32-char hex string. */
        private String passLm = "";

        /** Pre-computed NT hash as a 32-char hex string. */
        private String passNt = "";

        /** Pre-computed NTLMv2 hash as a 32-char hex string (tied to a specific user+domain). */
        private String passNtlm2 = "";

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getWorkstation() {
            return workstation;
        }

        public void setWorkstation(String workstation) {
            this.workstation = workstation;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getPassLm() {
            return passLm;
        }

        public void setPassLm(String passLm) {
            this.passLm = passLm;
        }

        public String getPassNt() {
            return passNt;
        }

        public void setPassNt(String passNt) {
            this.passNt = passNt;
        }

        public String getPassNtlm2() {
            return passNtlm2;
        }

        public void setPassNtlm2(String passNtlm2) {
            this.passNtlm2 = passNtlm2;
        }
    }
}
