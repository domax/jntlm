package net.domax.jntlm.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.proxy.Endpoint;
import net.domax.jntlm.proxy.RequestForwarder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

/**
 * The listening proxy server &mdash; a port of CNTLM's accept loop in {@code main.c}.
 *
 * <p>Managed by Spring as a {@link SmartLifecycle} bean: on startup it binds a {@link ServerSocket}
 * to the configured address/port and runs an accept loop on a dedicated virtual thread; each
 * accepted client is dispatched to a virtual-thread-per-task executor and handled by a
 * {@link ClientConnectionHandler}. Mirrors CNTLM's thread-per-connection model using Java virtual
 * threads. Shutdown closes the listening socket and the executor.
 */
@Component
public class ProxyServer implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(ProxyServer.class);

    private final JntlmProperties properties;
    private final RequestForwarder forwarder;

    private volatile boolean running;
    private ServerSocket serverSocket;
    private ExecutorService clientExecutor;
    private Thread acceptThread;

    public ProxyServer(JntlmProperties properties, RequestForwarder forwarder) {
        this.properties = properties;
        this.forwarder = forwarder;
    }

    @Override
    public synchronized void start() {
        if (running) {
            return;
        }
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(
                    properties.getListenAddress(), properties.getListenPort()));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to bind proxy listener on "
                    + properties.getListenAddress() + ":" + properties.getListenPort(), e);
        }
        clientExecutor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("jntlm-client-", 0).factory());
        running = true;
        acceptThread = new Thread(this::acceptLoop, "jntlm-accept");
        // Non-daemon: keeps the JVM alive for this non-web Spring Boot application.
        acceptThread.setDaemon(false);
        acceptThread.start();
        log.info("jntlm proxy listening on {}:{}",
                properties.getListenAddress(), properties.getListenPort());
    }

    private void acceptLoop() {
        while (running) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    log.warn("accept() failed: {}", e.getMessage());
                }
                break;
            }
            try {
                socket.setTcpNoDelay(true);
                Endpoint client = new Endpoint(socket);
                clientExecutor.execute(new ClientConnectionHandler(client, forwarder));
            } catch (IOException e) {
                log.warn("Failed to set up client connection: {}", e.getMessage());
                closeQuietly(socket);
            }
        }
    }

    @Override
    public synchronized void stop() {
        if (!running) {
            return;
        }
        running = false;
        closeServerSocket();
        if (acceptThread != null) {
            acceptThread.interrupt();
        }
        if (clientExecutor != null) {
            clientExecutor.shutdownNow();
        }
        log.info("jntlm proxy stopped");
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    private void closeServerSocket() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // ignore
            }
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // ignore
        }
    }
}
