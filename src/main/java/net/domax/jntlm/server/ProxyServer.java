/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.proxy.Endpoint;
import net.domax.jntlm.proxy.ErrorPages;
import net.domax.jntlm.proxy.RequestForwarder;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Service;

/**
 * The listening proxy server &mdash; a port of CNTLM's accept loop in {@code main.c}.
 *
 * <p>Managed by Spring as a {@link SmartLifecycle} bean: on startup it binds a {@link ServerSocket}
 * to the configured address/port and runs an accept loop on a dedicated virtual thread; each
 * accepted client is dispatched to a virtual-thread-per-task executor and handled by a {@link
 * ClientConnectionHandler}. Mirrors CNTLM's thread-per-connection model using Java virtual threads.
 * Shutdown closes the listening socket and the executor.
 *
 * <p>Not in CNTLM: accepted sockets get {@code jntlm.limits.client-idle-timeout} as read timeout;
 * at most {@code jntlm.limits.max-client-connections} are served concurrently (extra ones receive
 * {@code 503} and are closed without contacting a parent); and a WARN is logged at startup when the
 * listener is reachable from other hosts without client authentication.
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class ProxyServer implements SmartLifecycle {

  private final JntlmProperties properties;
  private final RequestForwarder forwarder;
  private final ExecutorService clientExecutor;
  private final ClientAuthenticator clientAuthenticator;

  private volatile boolean running;
  private ServerSocket serverSocket;
  private Thread acceptThread;
  private Semaphore permits;
  private int clientSoTimeout;

  /**
   * Starts the proxy server: binds the listening socket and starts the accept loop. If already
   * running, does nothing.
   */
  @Override
  public synchronized void start() {
    if (running) return;

    try {
      serverSocket = new ServerSocket();
      serverSocket.setReuseAddress(true);
      serverSocket.bind(
          new InetSocketAddress(properties.getListenAddress(), properties.getListenPort()));
    } catch (IOException e) {
      throw new IllegalStateException(
          "Unable to bind proxy listener on "
              + properties.getListenAddress()
              + ":"
              + properties.getListenPort(),
          e);
    }
    val limits = properties.getLimits();
    clientSoTimeout = JntlmConfig.toSoTimeout(limits.getClientIdleTimeout());
    permits =
        limits.getMaxClientConnections() > 0
            ? new Semaphore(limits.getMaxClientConnections(), true)
            : null;
    warnIfExposed();

    running = true;
    acceptThread = new Thread(this::acceptLoop, "jntlm-accept");
    // Non-daemon: keeps the JVM alive for this non-web Spring Boot application.
    acceptThread.setDaemon(false);
    acceptThread.start();
    log.info(
        "jntlm proxy listening on {}:{}",
        properties.getListenAddress(),
        properties.getListenPort());
  }

  @SuppressWarnings("java:S135")
  private void acceptLoop() {
    while (running) {
      final Socket socket;
      try {
        socket = serverSocket.accept();
      } catch (IOException e) {
        if (running) log.warn("accept() failed: {}", e.toString());
        break;
      }
      if (permits != null && !permits.tryAcquire()) {
        rejectOverLimit(socket);
        continue;
      }
      final Runnable release = permits == null ? () -> {} : permits::release;
      try {
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(clientSoTimeout);
        val client = new Endpoint(socket);
        clientExecutor.execute(
            new ClientConnectionHandler(client, forwarder, clientAuthenticator, release));
        log.atDebug()
            .setMessage("Accepted client connection from {}")
            .addArgument(socket::getRemoteSocketAddress)
            .log();
      } catch (IOException | RejectedExecutionException e) {
        log.warn("Failed to set up client connection: {}", e.getMessage());
        closeQuietly(socket);
        release.run();
      }
    }
  }

  /**
   * Answers a connection over {@code max-client-connections} with {@code 503} on a separate virtual
   * thread (so a slow peer never blocks {@code accept}), then lingers up to 1 s draining its
   * request so the reply is not lost to a TCP reset.
   */
  private void rejectOverLimit(Socket socket) {
    log.warn(
        "Rejecting client {}: jntlm.limits.max-client-connections reached",
        socket.getRemoteSocketAddress());
    Thread.ofVirtual()
        .start(() -> {
          try (socket) {
            socket.setSoTimeout(1000);
            ErrorPages.send(socket.getOutputStream(), 503, "Too many client connections.", null);
            socket.shutdownOutput();
            val in = socket.getInputStream();
            val buf = new byte[4096];
            var total = 0;
            int r;
            while (total < 65536 && (r = in.read(buf)) > 0) total += r;
          } catch (IOException ignored) {
            // best effort
          }
        });
  }

  /** Logs one WARN when the listener is reachable from other hosts without client auth. */
  private void warnIfExposed() {
    val address = serverSocket.getInetAddress();
    if (address.isLoopbackAddress() || clientAuthenticator.enabled()) return;
    log.warn(
        "jntlm proxy listens on non-loopback address {} without client authentication: anyone who"
            + " can reach this port can use your NTLM credentials. Enable jntlm.client-auth.enabled"
            + " or bind jntlm.listen-address to 127.0.0.1.",
        address.getHostAddress());
  }

  /** Returns the bound local port (useful when configured with port {@code 0}), or -1. */
  public int localPort() {
    val ss = serverSocket;
    return ss == null ? -1 : ss.getLocalPort();
  }

  /**
   * Stops the proxy server: closes the listening socket, interrupts the accept thread, and shuts
   * down the client executor. If already stopped, does nothing.
   */
  @Override
  public synchronized void stop() {
    if (!running) return;

    running = false;
    closeServerSocket();
    if (acceptThread != null) acceptThread.interrupt();
    if (clientExecutor != null) clientExecutor.shutdownNow();
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
