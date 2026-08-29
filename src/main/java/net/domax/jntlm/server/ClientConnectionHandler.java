/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.http.HttpIo;
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
 */
@Slf4j
@RequiredArgsConstructor
public final class ClientConnectionHandler implements Runnable {

  private final Endpoint client;
  private final RequestForwarder forwarder;

  @SuppressWarnings("java:S135")
  @Override
  public void run() {
    try {
      while (true) {
        val request = HttpIo.recvHeaders(client.in());
        if (request == null) break;

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
    }
  }
}
