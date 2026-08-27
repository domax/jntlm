package net.domax.jntlm.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import net.domax.jntlm.config.JntlmProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Manages the ordered list of parent proxies and connects to them with failover.
 *
 * <p>Ports CNTLM's {@code proxy_connect} parent-selection and failover model: a single shared
 * "current" parent is used by all connections; when it fails, a round-robin scan finds the next
 * working parent, migrates everyone to it and flushes the cached-connection pool.
 */
@Component
public class ParentProxyManager {

    private static final Logger log = LoggerFactory.getLogger(ParentProxyManager.class);

    private static final int CONNECT_TIMEOUT_MS = 10_000;

    private final List<ParentProxy> parents = new ArrayList<>();
    private final ConnectionPool connectionPool;

    private int current;

    public ParentProxyManager(JntlmProperties properties, ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
        for (String spec : properties.getParents()) {
            if (spec != null && !spec.isBlank()) {
                parents.add(ParentProxy.parse(spec));
            }
        }
        if (parents.isEmpty()) {
            throw new IllegalStateException("No parent proxies configured (jntlm.parents)");
        }
    }

    public List<ParentProxy> getParents() {
        return List.copyOf(parents);
    }

    /**
     * Connects to a working parent proxy, applying round-robin failover. If the working parent
     * differs from the previously active one, the connection pool is flushed and the active
     * parent updated so all connections migrate to it.
     *
     * @return a connected socket to a parent proxy
     * @throws IOException if no parent proxy on the list can be reached
     */
    public Socket connect() throws IOException {
        int start;
        synchronized (this) {
            start = current;
        }

        for (int i = 0; i < parents.size(); i++) {
            int idx = (start + i) % parents.size();
            ParentProxy p = parents.get(idx);
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(p.host(), p.port()), CONNECT_TIMEOUT_MS);
                socket.setTcpNoDelay(true);
                if (idx != start) {
                    log.info("Switched to parent proxy {}", p);
                    onParentSwitched(idx);
                }
                return socket;
            } catch (IOException e) {
                log.warn("Proxy connect to {} failed ({}), will try the next one", p, e.getMessage());
            }
        }
        throw new IOException("No proxy on the list works.");
    }

    /** Updates the active parent and flushes cached connections bound to the previous parent. */
    private synchronized void onParentSwitched(int newIndex) {
        connectionPool.invalidateAll();
        current = newIndex;
    }
}
