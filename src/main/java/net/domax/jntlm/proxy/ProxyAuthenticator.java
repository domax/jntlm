package net.domax.jntlm.proxy;

import java.io.IOException;
import java.util.Base64;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.ntlm.Credentials;
import net.domax.jntlm.ntlm.NtlmMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Performs the NTLM authentication handshake with a parent proxy over a single connection.
 *
 * <p>Direct port of CNTLM's {@code proxy_authenticate} ({@code proxy.c}). The handshake is:
 * <ol>
 *   <li>send the request as a body-less probe carrying {@code Proxy-Authorization: NTLM
 *       <base64 Type-1>};</li>
 *   <li>read the proxy reply; if it is {@code 407} with {@code Proxy-Authenticate: NTLM
 *       <base64 Type-2>}, compute the Type-3 message and inject it back into the caller's
 *       {@code request} as a new {@code Proxy-Authorization} header;</li>
 *   <li>if the proxy did not challenge but the request was HEAD or had a body, force a
 *       {@code 407} reply so the caller re-issues the full request ({@code pretend407}).</li>
 * </ol>
 * The caller ({@link RequestForwarder}) then sends the now-authorized {@code request}.
 */
@Component
public class ProxyAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(ProxyAuthenticator.class);

    private static final int NTLM_CHALLENGE_MIN = 40;

    private final ParentProxyManager parentProxyManager;

    public ProxyAuthenticator(ParentProxyManager parentProxyManager) {
        this.parentProxyManager = parentProxyManager;
    }

    /**
     * Result of an authentication attempt.
     *
     * @param ok     {@code true} if the proxy replied (network OK); {@code false} on I/O failure
     * @param server the (possibly reconnected) parent-proxy endpoint
     * @param reply  the proxy's reply to the probe (its code drives the caller's next step)
     */
    public record AuthResult(boolean ok, Endpoint server, HttpMessage reply) {
    }

    /**
     * Runs the handshake on {@code server}. On success, if the proxy required authentication,
     * {@code request} is mutated to carry the final NTLM {@code Proxy-Authorization} header.
     */
    public AuthResult authenticate(Endpoint server, HttpMessage request, Credentials creds) {
        // Type-1 (negotiate) message.
        byte[] type1 = NtlmMessages.type1Request(creds);
        String type1Header = "NTLM " + Base64.getEncoder().encodeToString(type1);

        HttpMessage probe = request.copy();
        probe.getHeaders().modify("Proxy-Authorization", type1Header);

        boolean pretend407 = request.isHead() || HttpIo.httpHasBody(request, null) != 0;

        // Some ISA proxies reject HEAD auth requests; probe as GET.
        if (request.isHead()) {
            probe.setMethod("GET");
        }
        probe.getHeaders().modify("Content-Length", "0");
        probe.getHeaders().remove("Transfer-Encoding");

        try {
            HttpIo.sendHeaders(server.out(), probe);
        } catch (IOException e) {
            server.close();
            return new AuthResult(false, server, null);
        }

        HttpMessage reply;
        try {
            reply = HttpIo.recvHeaders(server.in());
        } catch (IOException e) {
            server.close();
            return new AuthResult(false, server, null);
        }
        if (reply == null) {
            server.close();
            return new AuthResult(false, server, null);
        }

        try {
            if (reply.getCode() == 407) {
                // Consume the challenge body so the connection can be reused.
                HttpIo.dropBody(server.in(), reply);

                String challengeHeader = reply.getHeaders().getFirst("Proxy-Authenticate");
                if (challengeHeader != null) {
                    byte[] challenge = decodeChallenge(challengeHeader);
                    if (challenge != null && challenge.length > NTLM_CHALLENGE_MIN) {
                        byte[] type3 = NtlmMessages.type3Response(challenge, creds);
                        String type3Header = "NTLM " + Base64.getEncoder().encodeToString(type3);
                        request.getHeaders().modify("Proxy-Authorization", type3Header);
                    } else {
                        log.error("Proxy returned an invalid NTLM challenge");
                        server.close();
                        return new AuthResult(false, server, null);
                    }
                } else {
                    log.warn("No Proxy-Authenticate header - NTLM/Negotiate not supported?");
                }
            } else if (pretend407) {
                // No auth was demanded, but we only sent a probe - force the caller to re-issue.
                reply.setCode(407);
                HttpIo.dropBody(server.in(), reply);
            }
        } catch (IOException e) {
            server.close();
            return new AuthResult(false, server, null);
        }

        // If the proxy closed the connection on us, reconnect for the caller.
        Endpoint activeServer = server;
        if (server.isPeerClosed()) {
            log.debug("Parent proxy closed the connection; reconnecting");
            server.close();
            try {
                activeServer = new Endpoint(parentProxyManager.connect());
            } catch (IOException e) {
                return new AuthResult(false, server, null);
            }
        }

        return new AuthResult(true, activeServer, reply);
    }

    /** Decodes the base64 NTLM Type-2 challenge from a {@code Proxy-Authenticate} header value. */
    private static byte[] decodeChallenge(String header) {
        String h = header.trim();
        if (h.length() < 5) {
            return null;
        }
        // Skip the "NTLM " (or "NTLM"/"Negotiate ") scheme prefix, as CNTLM does (tmp + 5).
        String b64 = h.substring(5).trim();
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
