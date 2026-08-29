/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import lombok.val;
import org.jspecify.annotations.NonNull;

/**
 * A parent proxy endpoint (host and port). DNS resolution is left to the socket layer at connect
 * time, mirroring CNTLM's lazy resolution in {@code proxy_connect}.
 */
public record ParentProxy(String host, int port) {

  /** Parses a {@code host:port} specification (supports bracketed IPv6 literals). */
  public static ParentProxy parse(String spec) {
    val s = spec.trim();
    final String host;
    final int colon;
    final int port;
    if (s.startsWith("[")) {
      val close = s.indexOf(']');
      if (close < 0) throw new IllegalArgumentException("Malformed IPv6 proxy spec: " + spec);
      host = s.substring(1, close);
      colon = s.indexOf(':', close);
      if (colon < 0) throw new IllegalArgumentException("Missing port in proxy spec: " + spec);
    } else {
      colon = s.lastIndexOf(':');
      if (colon < 0) throw new IllegalArgumentException("Missing port in proxy spec: " + spec);
      host = s.substring(0, colon);
    }
    port = Integer.parseInt(s.substring(colon + 1).trim());
    if (host.isEmpty() || port <= 0 || port > 65535)
      throw new IllegalArgumentException("Invalid proxy spec: " + spec);

    return new ParentProxy(host, port);
  }

  @Override
  public @NonNull String toString() {
    return host + ":" + port;
  }
}
