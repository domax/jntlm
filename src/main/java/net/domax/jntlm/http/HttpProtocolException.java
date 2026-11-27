/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import java.io.IOException;
import lombok.Getter;
import lombok.experimental.Accessors;

/**
 * A malformed, ambiguous or oversized HTTP message. Not in CNTLM (its parser is lenient).
 *
 * <p>Extends {@link IOException} so every existing "I/O failed &rarr; close" path keeps working;
 * call sites that can still answer the client use {@link #status()} ({@code 400}, {@code 431} or
 * {@code 502}) to pick the error reply.
 */
@Getter
@Accessors(fluent = true)
public final class HttpProtocolException extends IOException {

  private final int status;

  public HttpProtocolException(int status, String reason) {
    super(reason);
    this.status = status;
  }
}
