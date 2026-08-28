/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import net.domax.jntlm.http.HttpMessage;

/**
 * Outcome of {@link RequestForwarder#forward}, mirroring the three return states of CNTLM's {@code
 * forward_request}:
 *
 * <ul>
 *   <li>{@link #close()} &mdash; the client connection must be closed (CNTLM {@code return -1});
 *   <li>{@link #done()} &mdash; the request/response cycle completed and the client connection may
 *       be kept alive (CNTLM {@code return NULL});
 *   <li>{@link #reroute(HttpMessage)} &mdash; the (pinned) parent connection cannot serve this
 *       request because its target host changed; the already-read request is handed back so the
 *       caller re-forwards it on a fresh connection (CNTLM {@code return rr_data}).
 * </ul>
 */
public record ForwardResult(Type type, HttpMessage rerouteRequest) {

  public enum Type {
    CLOSE,
    DONE,
    REROUTE
  }

  public static ForwardResult close() {
    return new ForwardResult(Type.CLOSE, null);
  }

  public static ForwardResult done() {
    return new ForwardResult(Type.DONE, null);
  }

  public static ForwardResult reroute(HttpMessage request) {
    return new ForwardResult(Type.REROUTE, request);
  }
}
