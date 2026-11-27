/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpLimits;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.http.HttpProtocolException;
import net.domax.jntlm.ntlm.Credentials;
import org.springframework.beans.factory.annotation.Autowired;
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
 *
 * <p>Not in CNTLM: framing errors and timeouts are answered with an error page (400/431 for a bad
 * client request, 502 for a bad parent response or failed parent authentication, 504 for a parent
 * read timeout) as long as nothing of the current response was sent yet; a parent connection is
 * pooled only after a cleanly framed exchange, and any unexpected exception closes (never pools)
 * the parent connection.
 */
@Slf4j
@Component
public class RequestForwarder {

  private static final String BASIC_REALM =
      "Basic realm=\"JNTLM proxy authentication failed, credentials are invalid\"";
  private static final String PARENT_CLOSED = "Parent proxy closed a reused connection.";

  private static final String PROXY_CONNECTION = "Proxy-Connection";
  private static final String PROXY_AUTHENTICATE = "Proxy-Authenticate";
  private static final String PROXY_AUTHORIZATION = "Proxy-Authorization";
  private static final String CONNECTION = "Connection";
  private static final String KEEP_ALIVE = "keep-alive";
  private static final String CLOSE = "close";

  private final ParentProxyManager parentProxyManager;
  private final ConnectionPool connectionPool;
  private final ProxyAuthenticator authenticator;
  private final Credentials globalCredentials;
  private final NtlmFlagsResolver flagsResolver;
  private final HttpLimits limits;
  private final Duration tunnelIdleTimeout;

  /** Creates a forwarder using {@link HttpLimits#DEFAULT} and no tunnel idle timeout. */
  public RequestForwarder(
      ParentProxyManager parentProxyManager,
      ConnectionPool connectionPool,
      ProxyAuthenticator authenticator,
      Credentials globalCredentials,
      NtlmFlagsResolver flagsResolver) {
    this(
        parentProxyManager,
        connectionPool,
        authenticator,
        globalCredentials,
        flagsResolver,
        HttpLimits.DEFAULT,
        Duration.ZERO);
  }

  @Autowired
  public RequestForwarder(
      ParentProxyManager parentProxyManager,
      ConnectionPool connectionPool,
      ProxyAuthenticator authenticator,
      Credentials globalCredentials,
      NtlmFlagsResolver flagsResolver,
      HttpLimits limits,
      JntlmProperties properties) {
    this(
        parentProxyManager,
        connectionPool,
        authenticator,
        globalCredentials,
        flagsResolver,
        limits,
        properties.getLimits().getTunnelIdleTimeout());
  }

  public RequestForwarder(
      ParentProxyManager parentProxyManager,
      ConnectionPool connectionPool,
      ProxyAuthenticator authenticator,
      Credentials globalCredentials,
      NtlmFlagsResolver flagsResolver,
      HttpLimits limits,
      Duration tunnelIdleTimeout) {
    this.parentProxyManager = parentProxyManager;
    this.connectionPool = connectionPool;
    this.authenticator = authenticator;
    this.globalCredentials = globalCredentials;
    this.flagsResolver = flagsResolver;
    this.limits = limits;
    this.tunnelIdleTimeout = tunnelIdleTimeout;
  }

  /** Header-read limits applied to client requests and parent responses. */
  public HttpLimits limits() {
    return limits;
  }

  /**
   * Forwards {@code initialRequest} (already read from {@code client}) and relays the response.
   *
   * @param client the client endpoint (its streams are used to read bodies / write the response)
   * @param initialRequest the request already parsed from the client
   * @return a {@link ForwardResult} describing what the caller should do next
   */
  @SuppressWarnings("java:S1181")
  public ForwardResult forward(Endpoint client, HttpMessage initialRequest) {
    val active = new Endpoint[1];
    try {
      return forward(client, initialRequest, active);
    } catch (RuntimeException | Error e) {
      // Not in CNTLM: an unexpected failure must never leave a half-used parent connection open
      // (or pooled).
      if (active[0] != null) active[0].close();
      throw e;
    }
  }

  @SuppressWarnings({"java:S3776", "java:S135", "java:S6541", "LabeledStatement"})
  private ForwardResult forward(Endpoint client, HttpMessage initialRequest, Endpoint[] active) {
    var request = initialRequest;
    var retry = false;
    String hostname = null;

    beginning:
    while (true) {
      Endpoint server;
      final Credentials creds;
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
        // Not in CNTLM: negotiate flags come from the (auto-detecting) resolver.
        creds.setFlags(flagsResolver.flagsFor(request));
        try {
          server = new Endpoint(parentProxyManager.connect());
          connectionPool.recordFreshConnection();
        } catch (IOException e) {
          log.error("Unable to connect to any parent proxy: {}", e.toString());
          trySend502(client, request);
          return ForwardResult.close();
        }
      }
      active[0] = server;

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
            data0 = HttpIo.recvHeaders(client.in(), limits);
          } catch (HttpProtocolException e) {
            // Not in CNTLM: reject a malformed keep-alive request instead of forwarding it.
            log.debug("Rejecting malformed client request: {}", e.getMessage());
            trySendError(client, e.status(), e.getMessage(), null);
            data0 = null;
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
                data1 = HttpIo.recvHeaders(server.in(), limits);
              } catch (HttpProtocolException e) {
                // Not in CNTLM: nothing of this response reached the client yet.
                log.warn("Malformed parent proxy response: {}", e.getMessage());
                trySendError(client, 502, "Malformed response from parent proxy.", data0);
                discard(server, creds);
                return ForwardResult.close();
              } catch (SocketTimeoutException e) {
                log.warn("Parent proxy response timed out");
                trySendError(client, 504, "Parent proxy response timed out.", data0);
                discard(server, creds);
                return ForwardResult.close();
              } catch (IOException e) {
                data1 = null;
              }
              if (data1 == null) {
                if (wasCached && HttpIo.httpHasBody(data0, null) == 0) {
                  retry = true;
                  request = data0;
                  server.close();
                  continue beginning;
                }
                // Not in CNTLM: a stale pooled connection swallowed a request with a body that
                // cannot be replayed - answer 502 instead of silently dropping the connection.
                if (wasCached) {
                  log.warn("Pooled parent connection closed before responding to a request body");
                  trySendError(client, 502, PARENT_CLOSED, data0);
                }
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
              // Not in CNTLM: tell the client why instead of silently closing.
              trySendError(client, ar.status(), "Parent proxy authentication failed.", data0);
              discard(server, creds);
              return ForwardResult.close();
            }
            server = ar.server();
            active[0] = server;
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

          // Not in CNTLM: a fresh handshake was rejected - let the resolver re-detect flags.
          if (loop == 1 && data1.getCode() == 407 && !wasCached && !noauth && !authok)
            flagsResolver.reportRejected(creds.getFlags());

          // Not in CNTLM: only a cleanly framed exchange may keep either connection alive.
          var reusable = true;
          if (loop == 1)
            reusable =
                HttpIo.isCleanlyFramed(data0, data1)
                    && !data0.getHeaders().containsToken(CONNECTION, CLOSE)
                    && !data1.getHeaders().containsToken(CONNECTION, CLOSE);

          // --- loop 1: normalize hop-by-hop headers for the client ---
          if (loop == 1) {
            connAlive = reusable && data1.getHeaders().containsToken(CONNECTION, KEEP_ALIVE);
            if (!connAlive && !(data0.isConnect() && data1.getCode() == 200))
              data1.getHeaders().modify(CONNECTION, CLOSE);
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
            // Not in CNTLM: small fixed-length bodies are coalesced with their headers.
            val flush = !HttpIo.hasSmallFixedBody(data0, loop == 0 ? null : data1);
            HttpIo.sendHeaders(wOut, current, flush);
          } catch (IOException e) {
            // Not in CNTLM: a stale pooled connection may fail on write instead of on read.
            if (loop == 0 && wasCached) {
              if (HttpIo.httpHasBody(data0, null) == 0) {
                retry = true;
                request = data0;
                server.close();
                continue beginning;
              }
              trySendError(client, 502, PARENT_CLOSED, data0);
            }
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
              HttpIo.tunnel(client.tunnelEnd(), server.tunnelEnd(), tunnelIdleTimeout);
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
            HttpIo.sendBody(wOut, rIn, data0, bodyResponse, limits);
          } catch (IOException e) {
            // Not in CNTLM: the request body hit a stale pooled connection (broken pipe/reset);
            // it cannot be replayed, so answer 502 rather than dropping the client silently.
            if (loop == 0 && wasCached && !(e instanceof SocketTimeoutException)) {
              log.warn(
                  "Pooled parent connection failed while sending a request body: {}", e.toString());
              trySendError(client, 502, PARENT_CLOSED, data0);
            }
            discard(server, creds);
            return ForwardResult.close();
          }

          // --- loop 1: decide whether the parent connection stays alive ---
          if (loop == 1) {
            proxyAlive =
                reusable
                    && data1.getHeaders().containsToken(PROXY_CONNECTION, KEEP_ALIVE)
                    && data0.getHttpVersion() >= 11;
            if (!proxyAlive) pendingResult = ForwardResult.close();
          }

          ++loop;
        }
      } while (connAlive && proxyAlive && !client.isPeerClosed());

      // Bailout: cache the parent connection for reuse, or close it.
      finishConnection(server, creds, proxyAlive, authok);
      return (pendingResult != null) ? pendingResult : ForwardResult.done();
    }
  }

  /** Caches the parent connection when it can still be reused, otherwise closes it. */
  private void finishConnection(
      Endpoint server, Credentials creds, boolean proxyAlive, boolean authok) {
    if (proxyAlive && authok) connectionPool.add(server, creds);
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

  private void trySendError(Endpoint client, int status, String detail, HttpMessage request) {
    try {
      ErrorPages.send(client.out(), status, detail, request == null ? null : request.getProtocol());
    } catch (IOException ignored) {
      // client is gone; nothing to do
    }
  }
}
