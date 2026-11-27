/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpLimits;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.ntlm.Credentials;
import net.domax.jntlm.ntlm.NtlmException;
import net.domax.jntlm.ntlm.NtlmMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Performs the NTLM authentication handshake with a parent proxy over a single connection.
 *
 * <p>Direct port of CNTLM's {@code proxy_authenticate} ({@code proxy.c}). The handshake is:
 *
 * <ol>
 *   <li>send the request as a body-less probe carrying {@code Proxy-Authorization: NTLM <base64
 *       Type-1>};
 *   <li>read the proxy reply; if it is {@code 407} with {@code Proxy-Authenticate: NTLM <base64
 *       Type-2>}, compute the Type-3 message and inject it back into the caller's {@code request}
 *       as a new {@code Proxy-Authorization} header;
 *   <li>if the proxy did not challenge but the request was HEAD or had a body, force a {@code 407}
 *       reply so the caller re-issues the full request ({@code pretend407}).
 * </ol>
 *
 * The caller ({@link RequestForwarder}) then sends the now-authorized {@code request}.
 */
@Slf4j
@Component
public class ProxyAuthenticator {

  private static final byte[] NO_CHALLENGE = new byte[0];

  private final ParentProxyManager parentProxyManager;
  private final HttpLimits limits;

  /** Creates an authenticator using {@link HttpLimits#DEFAULT}. */
  public ProxyAuthenticator(ParentProxyManager parentProxyManager) {
    this(parentProxyManager, HttpLimits.DEFAULT);
  }

  @Autowired
  public ProxyAuthenticator(ParentProxyManager parentProxyManager, HttpLimits limits) {
    this.parentProxyManager = parentProxyManager;
    this.limits = limits;
  }

  /**
   * Result of an authentication attempt.
   *
   * @param ok {@code true} if the proxy replied (network OK); {@code false} on failure
   * @param server the (possibly reconnected) parent-proxy endpoint
   * @param reply the proxy's reply to the probe (its code drives the caller's next step)
   * @param status on failure, the status to answer the client with ({@code 502}, or {@code 504} on
   *     a parent read timeout); {@code 0} on success. Not in CNTLM.
   */
  public record AuthResult(boolean ok, Endpoint server, HttpMessage reply, int status) {

    static AuthResult failed(Endpoint server, IOException cause) {
      return new AuthResult(
          false, server, null, cause instanceof SocketTimeoutException ? 504 : 502);
    }
  }

  /**
   * Runs the handshake on {@code server}. On success, if the proxy required authentication, {@code
   * request} is mutated to carry the final NTLM {@code Proxy-Authorization} header.
   */
  @SuppressWarnings({"java:S3776", "java:S1141"})
  public AuthResult authenticate(Endpoint server, HttpMessage request, Credentials creds) {
    // Type-1 (negotiate) message.
    val type1 = NtlmMessages.type1Request(creds);
    val type1Header = "NTLM " + Base64.getEncoder().encodeToString(type1);

    val probe = request.copy();
    probe.getHeaders().modify("Proxy-Authorization", type1Header);

    boolean pretend407 = request.isHead() || HttpIo.httpHasBody(request, null) != 0;

    // Some ISA proxies reject HEAD auth requests; probe as GET.
    if (request.isHead()) probe.setMethod("GET");
    probe.getHeaders().modify("Content-Length", "0");
    probe.getHeaders().remove("Transfer-Encoding");

    try {
      HttpIo.sendHeaders(server.out(), probe);
    } catch (IOException e) {
      server.close();
      return AuthResult.failed(server, e);
    }

    final HttpMessage reply;
    try {
      reply = HttpIo.recvHeaders(server.in(), limits);
    } catch (IOException e) {
      log.debug("Parent proxy auth reply unreadable: {}", e.toString());
      server.close();
      return AuthResult.failed(server, e);
    }
    if (reply == null) {
      server.close();
      return AuthResult.failed(server, null);
    }

    try {
      if (reply.getCode() == 407) {
        // Consume the challenge body so the connection can be reused.
        HttpIo.dropBody(server.in(), reply, limits);

        val challengeHeader = reply.getHeaders().getFirst("Proxy-Authenticate");
        if (challengeHeader != null) {
          val challenge = decodeChallenge(challengeHeader);
          final byte[] type3;
          try {
            type3 = NtlmMessages.type3Response(challenge, creds);
          } catch (NtlmException e) {
            // Not in CNTLM: Type-2 validation replaces its "length > 40" check (see NtlmMessages).
            log.error("Proxy returned an invalid NTLM challenge: {}", e.getMessage());
            server.close();
            return AuthResult.failed(server, null);
          }
          val type3Header = "NTLM " + Base64.getEncoder().encodeToString(type3);
          request.getHeaders().modify("Proxy-Authorization", type3Header);
        } else log.warn("No Proxy-Authenticate header - NTLM/Negotiate not supported?");
      } else if (pretend407) {
        // No auth was demanded, but we only sent a probe - force the caller to re-issue.
        reply.setCode(407);
        HttpIo.dropBody(server.in(), reply, limits);
      }
    } catch (IOException e) {
      server.close();
      return AuthResult.failed(server, e);
    }

    // If the proxy closed the connection on us, reconnect for the caller.
    var activeServer = server;
    if (server.isPeerClosed()) {
      log.debug("Parent proxy closed the connection; reconnecting");
      server.close();
      try {
        activeServer = new Endpoint(parentProxyManager.connect());
      } catch (IOException e) {
        return AuthResult.failed(server, e);
      }
    }

    return new AuthResult(true, activeServer, reply, 0);
  }

  /** Decodes the base64 NTLM Type-2 challenge from a {@code Proxy-Authenticate} header value. */
  static byte[] decodeChallenge(String header) {
    val h = header.trim();
    if (h.length() < 5) return NO_CHALLENGE;

    // Skip the "NTLM " (or "NTLM"/"Negotiate ") scheme prefix, as CNTLM does (tmp + 5).
    val b64 = h.substring(5).trim();
    try {
      return Base64.getDecoder().decode(b64);
    } catch (IllegalArgumentException e) {
      return NO_CHALLENGE;
    }
  }
}
