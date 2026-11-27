/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import lombok.Getter;
import lombok.experimental.Accessors;
import net.domax.jntlm.http.HttpInputStream;
import net.domax.jntlm.http.HttpIo;

/**
 * A TCP endpoint (client or parent proxy) wrapping a {@link Socket} with buffered streams.
 *
 * <p>Provides a best-effort {@link #isPeerClosed()} check equivalent to CNTLM's {@code so_closed}:
 * it peeks with a short timeout to detect whether the remote side has closed the connection,
 * without losing pending data.
 *
 * <p>Not in CNTLM: input is an unsynchronized {@link HttpInputStream} with fast line scanning, and
 * the unbuffered socket output ({@link #rawOut()}) is exposed for the CONNECT tunnel relay.
 */
@Getter
@Accessors(fluent = true)
public final class Endpoint implements Closeable {

  private final Socket socket;
  private final HttpInputStream in;
  private final OutputStream out;
  private final OutputStream rawOut;

  public Endpoint(Socket socket) throws IOException {
    this.socket = socket;
    this.in = new HttpInputStream(socket.getInputStream());
    this.rawOut = socket.getOutputStream();
    this.out = new BufferedOutputStream(rawOut, HttpIo.OUTPUT_BUFFER_SIZE);
  }

  /**
   * Returns true if the peer has closed the connection. Buffered unread data means open; otherwise
   * a read is attempted under a 1&nbsp;ms timeout: EOF means closed, data means open (and is kept
   * buffered), a timeout means open with no pending data.
   */
  public boolean isPeerClosed() {
    return in.peekClosed(socket);
  }

  /** This endpoint's streams as one side of a CONNECT tunnel. */
  public HttpIo.TunnelEnd tunnelEnd() {
    return new HttpIo.TunnelEnd(in, out, rawOut, socket);
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
