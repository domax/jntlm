/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.ntlm.Credentials;
import org.springframework.stereotype.Component;

/**
 * Core request-forwarding engine &mdash; a faithful port of CNTLM's {@code forward_request} ({@code
 * forward.c}).
 *
 * <p>For a single client request it: acquires a parent-proxy connection (reusing a cached,
 * already-authenticated one when possible, otherwise connecting with failover); performs the NTLM
 * handshake when required; relays the request to the parent and the response back to the client;
 * tunnels {@code CONNECT}; honors HTTP keep-alive on both sides; retries once on a stale cached
 * connection; and finally caches the parent connection for reuse when it can still be used.
 *
 * <p>The intricate two-pass ({@code loop 0} = client&rarr;parent, {@code loop 1} =
 * parent&rarr;client) control flow with CNTLM's {@code goto shortcut}/{@code goto beginning}/{@code
 * goto bailout} jumps is reproduced with labeled loops and a {@code shortcut} flag.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class RequestForwarder {

  private static final String BASIC_REALM =
      "Basic realm=\"JNTLM proxy authentication failed, credentials are invalid\"";

  private static final String PROXY_CONNECTION = "Proxy-Connection";
  private static final String PROXY_AUTHENTICATE = "Proxy-Authenticate";
  private static final String PROXY_AUTHORIZATION = "Proxy-Authorization";
  private static final String CONNECTION = "Connection";
  private static final String KEEP_ALIVE = "keep-alive";

  private final ParentProxyManager parentProxyManager;
  private final ConnectionPool connectionPool;
  private final ProxyAuthenticator authenticator;
  private final Credentials globalCredentials;

  /**
   * Forwards {@code initialRequest} (already read from {@code client}) and relays the response.
   *
   * @param client the client endpoint (its streams are used to read bodies / write the response)
   * @param initialRequest the request already parsed from the client
   * @return a {@link ForwardResult} describing what the caller should do next
   */
  @SuppressWarnings({"java:S3776", "java:S135", "LabeledStatement"})
  public ForwardResult forward(Endpoint client, HttpMessage initialRequest) {
    var request = initialRequest;
    var retry = false;
    String hostname = null;

    beginning:
    while (true) {
      Endpoint server;
      Credentials creds;
      boolean wasCached = false;
      boolean authok = false;
      boolean noauth = false;

      val cached = connectionPool.pop();
      if (cached != null) {
        server = cached.endpoint();
        creds = cached.credentials();
        authok = true;
        wasCached = true;
      } else {
        creds = globalCredentials.copy();
        try {
          server = new Endpoint(parentProxyManager.connect());
        } catch (IOException e) {
          log.error("Unable to connect to any parent proxy: {}", e.toString());
          trySend502(client, request);
          return ForwardResult.close();
        }
      }

      if (hostname == null && request != null && request.getHost() != null)
        hostname = request.getHost();

      boolean connAlive;
      boolean proxyAlive;
      ForwardResult pendingResult = null;

      do {
        HttpMessage data0;
        if (request != null) {
          data0 = retry ? request : request.copy();
          request = null;
        } else {
          try {
            data0 = HttpIo.recvHeaders(client.in());
          } catch (IOException e) {
            data0 = null;
          }
          if (data0 == null) {
            discard(server, creds);
            return ForwardResult.close();
          }
        }

        retry = false;
        connAlive = false;
        proxyAlive = false;
        HttpMessage data1 = null;
        int loop = 0;
        boolean shortcut = false;
        while (loop < 2) {
          if (!shortcut) {
            if (loop == 1) {
              try {
                data1 = HttpIo.recvHeaders(server.in());
              } catch (IOException e) {
                data1 = null;
              }
              if (data1 == null) {
                discard(server, creds);
                return ForwardResult.close();
              }
            }
            // Pinned parent connection cannot serve a different host: hand the request back.
            if (loop == 0
                && hostname != null
                && data0.getHost() != null
                && !hostname.equalsIgnoreCase(data0.getHost())) {
              if (authok
                  && data0.getHttpVersion() >= 11
                  && (data0.getHeaders().containsToken(PROXY_CONNECTION, KEEP_ALIVE)
                      || data0.getHeaders().containsToken(CONNECTION, KEEP_ALIVE)))
                proxyAlive = true;

              finishConnection(server, creds, proxyAlive, authok);
              return ForwardResult.reroute(data0);
            }
          }
          shortcut = false;

          // --- loop 0: rewrite request headers before sending to the parent ---
          if (loop == 0 && data0.isRequest()) {
            if (data0.getHttpVersion() >= 11)
              data0.getHeaders().modify(PROXY_CONNECTION, KEEP_ALIVE);

            // Drop any Proxy-Authorization the client sent; we manage NTLM ourselves.
            data0.getHeaders().remove(PROXY_AUTHORIZATION);
          }

          // --- loop 0: authenticate with the parent when needed ---
          if (loop == 0 && data0.isRequest() && !authok && !noauth) {
            val ar = authenticator.authenticate(server, data0, creds);
            log.debug(
                "Parent auth result: ok={}, code={}",
                ar.ok(),
                ar.reply() == null ? null : ar.reply().getCode());
            if (!ar.ok()) {
              discard(server, creds);
              return ForwardResult.close();
            }
            server = ar.server();
            data1 = ar.reply();
            if (data1 != null && data1.getCode() != 407) {
              // Parent accepted (or errored) without a challenge: skip straight to
              // relaying this reply to the client (CNTLM's "goto shortcut").
              if (data1.getCode() < 400) noauth = true;
              loop = 1;
              shortcut = true;
              continue;
            }
            // A real 407 challenge was handled; data0 now carries the Type-3 header.
            // Reset data1 so loop 1 reads the genuine response.
            data1 = null;
          }

          // --- loop 1: a cached/uncredentialed connection went stale -> retry fresh ---
          if (loop == 1 && data1.getCode() == 407 && (wasCached || noauth)) {
            log.debug("Cached parent connection rejected auth; retrying on a fresh one");
            retry = true;
            request = data0;
            server.close();
            continue beginning;
          }

          // --- loop 1: mark the connection authenticated ---
          if (loop == 1 && !noauth && data1.getCode() != 407) authok = true;

          // --- loop 1: normalize hop-by-hop headers for the client ---
          if (loop == 1) {
            connAlive = data1.getHeaders().containsToken(CONNECTION, KEEP_ALIVE);
            if (!connAlive && !(data0.isConnect() && data1.getCode() == 200))
              data1.getHeaders().modify(CONNECTION, "close");
            data1.getHeaders().remove(PROXY_AUTHENTICATE);
            if (data1.getCode() == 407) data1.getHeaders().modify(PROXY_AUTHENTICATE, BASIC_REALM);
          }

          // --- send headers (loop 0 -> parent, loop 1 -> client) ---
          val current = (loop == 0) ? data0 : data1;
          val wOut = (loop == 0) ? server.out() : client.out();

          log.atDebug()
              .setMessage("Forwarding {} {} to {}")
              .addArgument(loop == 0 ? "request" : "response")
              .addArgument(current)
              .addArgument(
                  loop == 0
                      ? server.socket()::getRemoteSocketAddress
                      : client.socket()::getRemoteSocketAddress)
              .log();
          try {
            HttpIo.sendHeaders(wOut, current);
          } catch (IOException e) {
            discard(server, creds);
            return ForwardResult.close();
          }

          // --- CONNECT tunnel: once the parent says 200, pump bytes both ways ---
          if (loop == 1 && data0.isConnect() && data1.getCode() == 200) {
            try {
              log.atDebug()
                  .setMessage("Tunneling: {} <-> {}")
                  .addArgument(client.socket()::getRemoteSocketAddress)
                  .addArgument(server.socket()::getRemoteSocketAddress)
                  .log();
              HttpIo.tunnel(
                  client.in(),
                  client.out(),
                  client.socket(),
                  server.in(),
                  server.out(),
                  server.socket());
            } catch (Exception ignored) {
              // tunnel closes both ends; nothing more to relay
            }
            discard(server, creds);
            return ForwardResult.close();
          }

          // --- send body (loop 0 = request body client->parent, loop 1 = response body) ---
          val rIn = (loop == 0) ? client.in() : server.in();
          val bodyResponse = (loop == 0) ? null : data1;
          try {
            HttpIo.sendBody(wOut, rIn, data0, bodyResponse);
          } catch (IOException e) {
            discard(server, creds);
            return ForwardResult.close();
          }

          // --- loop 1: decide whether the parent connection stays alive ---
          if (loop == 1) {
            proxyAlive =
                data1.getHeaders().containsToken(PROXY_CONNECTION, KEEP_ALIVE)
                    && data0.getHttpVersion() >= 11;
            if (!proxyAlive) pendingResult = ForwardResult.close();
          }

          ++loop;
        }
      } while (connAlive && proxyAlive && !server.isPeerClosed() && !client.isPeerClosed());

      // Bailout: cache the parent connection for reuse, or close it.
      finishConnection(server, creds, proxyAlive, authok);
      return (pendingResult != null) ? pendingResult : ForwardResult.done();
    }
  }

  /** Caches the parent connection when it can still be reused, otherwise closes it. */
  private void finishConnection(
      Endpoint server, Credentials creds, boolean proxyAlive, boolean authok) {
    if (proxyAlive && authok && !server.isPeerClosed()) connectionPool.add(server, creds);
    else discard(server, creds);
  }

  /** Closes the parent connection and drops its credentials (no caching). */
  private void discard(Endpoint server, Credentials creds) {
    log.debug("Discarding connection with {} to parent proxy", creds);
    server.close();
  }

  private void trySend502(Endpoint client, HttpMessage request) {
    try {
      ErrorPages.send502(client.out(), request == null ? null : request.getProtocol());
    } catch (IOException ignored) {
      // client is gone; nothing to do
    }
  }
}
