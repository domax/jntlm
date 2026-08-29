/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * A TCP endpoint (client or parent proxy) wrapping a {@link Socket} with buffered streams.
 *
 * <p>Provides a best-effort {@link #isPeerClosed()} check equivalent to CNTLM's {@code so_closed}:
 * it peeks a single byte with a short timeout to detect whether the remote side has closed the
 * connection, without consuming pending data.
 */
public final class Endpoint implements Closeable {

  private final Socket socket;
  private final BufferedInputStream in;
  private final OutputStream out;

  public Endpoint(Socket socket) throws IOException {
    this.socket = socket;
    this.in = new BufferedInputStream(socket.getInputStream());
    this.out = new BufferedOutputStream(socket.getOutputStream());
  }

  public Socket socket() {
    return socket;
  }

  public InputStream in() {
    return in;
  }

  public OutputStream out() {
    return out;
  }

  /**
   * Returns true if the peer has closed the connection. Peeks one byte under a 1ms read timeout:
   * EOF means closed; a byte means still open (and is pushed back); a timeout means open with no
   * pending data.
   */
  public boolean isPeerClosed() {
    if (socket.isClosed() || !socket.isConnected()) return true;

    int oldTimeout;
    try {
      oldTimeout = socket.getSoTimeout();
    } catch (IOException e) {
      return true;
    }

    try {
      socket.setSoTimeout(1);
      in.mark(2);
      int b = in.read();
      if (b == -1) return true;

      in.reset();
      return false;
    } catch (SocketTimeoutException e) {
      return false;
    } catch (IOException e) {
      return true;
    } finally {
      try {
        socket.setSoTimeout(oldTimeout);
      } catch (IOException ignored) {
        // ignore
      }
    }
  }

  @Override
  public void close() {
    try {
      if (!socket.isClosed()) socket.close();
    } catch (IOException ignored) {
      // ignore
    }
  }
}
