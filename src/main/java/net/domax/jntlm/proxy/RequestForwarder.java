package net.domax.jntlm.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.ntlm.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Core request-forwarding engine &mdash; a faithful port of CNTLM's {@code forward_request}
 * ({@code forward.c}).
 *
 * <p>For a single client request it: acquires a parent-proxy connection (reusing a cached,
 * already-authenticated one when possible, otherwise connecting with failover); performs the NTLM
 * handshake when required; relays the request to the parent and the response back to the client;
 * tunnels {@code CONNECT}; honours HTTP keep-alive on both sides; retries once on a stale cached
 * connection; and finally caches the parent connection for reuse when it can still be used.
 *
 * <p>The intricate two-pass ({@code loop 0} = client&rarr;parent, {@code loop 1} = parent&rarr;client)
 * control flow with CNTLM's {@code goto shortcut}/{@code goto beginning}/{@code goto bailout} jumps
 * is reproduced with labelled loops and a {@code shortcut} flag.
 */
@Component
public class RequestForwarder {

    private static final Logger log = LoggerFactory.getLogger(RequestForwarder.class);

    private static final String BASIC_REALM =
            "Basic realm=\"Cntlm proxy authentication failed, credentials are invalid\"";

    private final ParentProxyManager parentProxyManager;
    private final ConnectionPool connectionPool;
    private final ProxyAuthenticator authenticator;
    private final Credentials globalCredentials;

    public RequestForwarder(ParentProxyManager parentProxyManager,
                            ConnectionPool connectionPool,
                            ProxyAuthenticator authenticator,
                            Credentials globalCredentials) {
        this.parentProxyManager = parentProxyManager;
        this.connectionPool = connectionPool;
        this.authenticator = authenticator;
        this.globalCredentials = globalCredentials;
    }

    /**
     * Forwards {@code initialRequest} (already read from {@code client}) and relays the response.
     *
     * @param client         the client endpoint (its streams are used to read bodies / write the response)
     * @param initialRequest the request already parsed from the client
     * @return a {@link ForwardResult} describing what the caller should do next
     */
    public ForwardResult forward(Endpoint client, HttpMessage initialRequest) {
        HttpMessage request = initialRequest;
        boolean retry = false;
        String hostname = null;

        beginning:
        while (true) {
            Endpoint server;
            Credentials tcreds;
            boolean wasCached = false;
            boolean authok = false;
            boolean noauth = false;

            ConnectionPool.PooledConnection cached = connectionPool.pop();
            if (cached != null) {
                server = cached.endpoint();
                tcreds = cached.credentials();
                authok = true;
                wasCached = true;
            } else {
                tcreds = globalCredentials.copy();
                try {
                    server = new Endpoint(parentProxyManager.connect());
                } catch (IOException e) {
                    log.error("Unable to connect to any parent proxy: {}", e.getMessage());
                    trySend502(client, request);
                    return ForwardResult.close();
                }
            }

            if (hostname == null && request != null && request.getHost() != null) {
                hostname = request.getHost();
            }

            boolean connAlive = false;
            boolean proxyAlive = false;
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
                        discard(server, tcreds);
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
                                discard(server, tcreds);
                                return ForwardResult.close();
                            }
                        }
                        // Pinned parent connection cannot serve a different host: hand the request back.
                        if (loop == 0 && hostname != null && data0.getHost() != null
                                && !hostname.equalsIgnoreCase(data0.getHost())) {
                            if (authok && data0.getHttpVersion() >= 11
                                    && (data0.getHeaders().containsToken("Proxy-Connection", "keep-alive")
                                        || data0.getHeaders().containsToken("Connection", "keep-alive"))) {
                                proxyAlive = true;
                            }
                            finishConnection(server, tcreds, proxyAlive, authok);
                            return ForwardResult.reroute(data0);
                        }
                    }
                    shortcut = false;

                    // --- loop 0: rewrite request headers before sending to the parent ---
                    if (loop == 0 && data0.isRequest()) {
                        if (data0.getHttpVersion() >= 11) {
                            data0.getHeaders().modify("Proxy-Connection", "keep-alive");
                        }
                        // Drop any Proxy-Authorization the client sent; we manage NTLM ourselves.
                        data0.getHeaders().remove("Proxy-Authorization");
                    }

                    // --- loop 0: authenticate with the parent when needed ---
                    if (loop == 0 && data0.isRequest() && !authok && !noauth) {
                        ProxyAuthenticator.AuthResult ar = authenticator.authenticate(server, data0, tcreds);
                        if (!ar.ok()) {
                            discard(server, tcreds);
                            return ForwardResult.close();
                        }
                        server = ar.server();
                        data1 = ar.reply();
                        if (data1.getCode() != 407) {
                            // Parent accepted (or errored) without a challenge: skip straight to
                            // relaying this reply to the client (CNTLM's "goto shortcut").
                            if (data1.getCode() < 400) {
                                noauth = true;
                            }
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
                    if (loop == 1 && !noauth && data1.getCode() != 407) {
                        authok = true;
                    }

                    // --- loop 1: normalise hop-by-hop headers for the client ---
                    if (loop == 1) {
                        connAlive = data1.getHeaders().containsToken("Connection", "keep-alive");
                        if (!connAlive && !(data0.isConnect() && data1.getCode() == 200)) {
                            data1.getHeaders().modify("Connection", "close");
                        }
                        data1.getHeaders().remove("Proxy-Authenticate");
                        if (data1.getCode() == 407) {
                            data1.getHeaders().modify("Proxy-Authenticate", BASIC_REALM);
                        }
                    }

                    // --- send headers (loop 0 -> parent, loop 1 -> client) ---
                    HttpMessage current = (loop == 0) ? data0 : data1;
                    OutputStream wOut = (loop == 0) ? server.out() : client.out();
                    try {
                        HttpIo.sendHeaders(wOut, current);
                    } catch (IOException e) {
                        discard(server, tcreds);
                        return ForwardResult.close();
                    }

                    // --- CONNECT tunnel: once the parent says 200, pump bytes both ways ---
                    if (loop == 1 && data0.isConnect() && data1.getCode() == 200) {
                        try {
                            HttpIo.tunnel(client.in(), client.out(), client.socket(),
                                    server.in(), server.out(), server.socket());
                        } catch (IOException ignored) {
                            // tunnel closes both ends; nothing more to relay
                        }
                        discard(server, tcreds);
                        return ForwardResult.close();
                    }

                    // --- send body (loop 0 = request body client->parent, loop 1 = response body) ---
                    InputStream rIn = (loop == 0) ? client.in() : server.in();
                    HttpMessage bodyResponse = (loop == 0) ? null : data1;
                    try {
                        HttpIo.sendBody(wOut, rIn, data0, bodyResponse);
                    } catch (IOException e) {
                        discard(server, tcreds);
                        return ForwardResult.close();
                    }

                    // --- loop 1: decide whether the parent connection stays alive ---
                    if (loop == 1) {
                        proxyAlive = data1.getHeaders().containsToken("Proxy-Connection", "keep-alive")
                                && data0.getHttpVersion() >= 11;
                        if (!proxyAlive) {
                            pendingResult = ForwardResult.close();
                        }
                    }

                    loop++;
                }
            } while (connAlive && proxyAlive && !server.isPeerClosed() && !client.isPeerClosed());

            // Bailout: cache the parent connection for reuse, or close it.
            finishConnection(server, tcreds, proxyAlive, authok);
            return (pendingResult != null) ? pendingResult : ForwardResult.done();
        }
    }

    /** Caches the parent connection when it can still be reused, otherwise closes it. */
    private void finishConnection(Endpoint server, Credentials tcreds, boolean proxyAlive, boolean authok) {
        if (proxyAlive && authok && !server.isPeerClosed()) {
            connectionPool.add(server, tcreds);
        } else {
            server.close();
        }
    }

    /** Closes the parent connection and drops its credentials (no caching). */
    private void discard(Endpoint server, Credentials tcreds) {
        server.close();
    }

    private void trySend502(Endpoint client, HttpMessage request) {
        try {
            ErrorPages.send502(client.out(), request == null ? null : request.getProtocol(),
                    "Bad Gateway");
        } catch (IOException ignored) {
            // client is gone; nothing to do
        }
    }
}
