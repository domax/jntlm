/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import java.io.IOException;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.proxy.Endpoint;
import net.domax.jntlm.proxy.ForwardResult;
import net.domax.jntlm.proxy.RequestForwarder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles a single client connection for its whole lifetime &mdash; a port of CNTLM's {@code
 * proxy_thread} ({@code main.c}).
 *
 * <p>Loops reading requests from the client and delegating each to {@link RequestForwarder}. A
 * {@link ForwardResult.Type#REROUTE} return means the forwarder handed the request back (its pinned
 * parent connection targeted a different host); the request is immediately re-forwarded on a fresh
 * connection. The loop ends when the forwarder asks to close or the client stops sending requests.
 */
public final class ClientConnectionHandler implements Runnable {

  private static final Logger log = LoggerFactory.getLogger(ClientConnectionHandler.class);

  private final Endpoint client;
  private final RequestForwarder forwarder;

  public ClientConnectionHandler(Endpoint client, RequestForwarder forwarder) {
    this.client = client;
    this.forwarder = forwarder;
  }

  @Override
  public void run() {
    try {
      while (true) {
        HttpMessage request = HttpIo.recvHeaders(client.in());
        if (request == null) {
          break;
        }

        ForwardResult result = forwarder.forward(client, request);
        // Follow reroutes until the request is actually served.
        while (result.type() == ForwardResult.Type.REROUTE) {
          result = forwarder.forward(client, result.rerouteRequest());
        }

        if (result.type() == ForwardResult.Type.CLOSE) {
          break;
        }
        // DONE: keep the client connection open for the next request (HTTP keep-alive).
      }
    } catch (IOException e) {
      log.debug("Client connection ended: {}", e.getMessage());
    } finally {
      client.close();
    }
  }
}
