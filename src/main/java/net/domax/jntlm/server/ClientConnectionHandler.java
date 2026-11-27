/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.ntlm.NtlmCrypto;
import net.domax.jntlm.proxy.Endpoint;
import net.domax.jntlm.proxy.ForwardResult;
import net.domax.jntlm.proxy.RequestForwarder;

/**
 * Handles a single client connection for its whole lifetime &mdash; a port of CNTLM's {@code
 * proxy_thread} ({@code main.c}).
 *
 * <p>Loops reading requests from the client and delegating each to {@link RequestForwarder}. A
 * {@link ForwardResult.Type#REROUTE} return means the forwarder handed the request back (its pinned
 * parent connection targeted a different host); the request is immediately re-forwarded on a fresh
 * connection. The loop ends when the forwarder asks to close or the client stops sending requests.
 *
 * <p>Not in CNTLM: when {@link ClientAuthenticator} is enabled, the first request on the connection
 * must carry valid BASIC {@code Proxy-Authorization} credentials before anything is forwarded;
 * otherwise a 407 challenge is sent and the connection is closed. Authentication is scoped to the
 * TCP connection, so later keep-alive requests (read here or inside {@link RequestForwarder}) are
 * not re-checked.
 */
@Slf4j
@RequiredArgsConstructor
public final class ClientConnectionHandler implements Runnable {

  private final Endpoint client;
  private final RequestForwarder forwarder;
  private final ClientAuthenticator clientAuth;

  @SuppressWarnings({"java:S135", "java:S3776"})
  @Override
  public void run() {
    var authenticated = !clientAuth.enabled();
    try {
      while (true) {
        val request = HttpIo.recvHeaders(client.in());
        if (request == null) break;

        if (!authenticated) {
          val check = clientAuth.check(request);
          val addr = client.socket().getRemoteSocketAddress();
          if (!check.accepted()) {
            if (check.username() == null) log.warn("Rejected client {}: {}", addr, check.reason());
            else
              log.warn(
                  "Rejected client {}: {} (user '{}')", addr, check.reason(), check.username());
            clientAuth.sendChallenge(client, request);
            break;
          }
          log.debug("Authenticated client {} as '{}'", addr, check.username());
          authenticated = true;
        }

        var result = forwarder.forward(client, request);
        // Follow reroutes until the request is actually served.
        while (result.type() == ForwardResult.Type.REROUTE)
          result = forwarder.forward(client, result.rerouteRequest());

        if (result.type() == ForwardResult.Type.CLOSE) break;
        // DONE: keep the client connection open for the next request (HTTP keep-alive).
      }
    } catch (IOException e) {
      log.debug("Client connection ended: {}", e.getMessage());
    } finally {
      client.close();
      NtlmCrypto.cleanup(); // Clean up thread-local crypto state to avoid memory leaks.
    }
  }
}
