/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.springframework.util.StringUtils.hasLength;

import java.net.URI;
import lombok.val;
import org.jspecify.annotations.NonNull;

/**
 * A parent proxy endpoint (host and port). DNS resolution is left to the socket layer at connect
 * time, mirroring CNTLM's lazy resolution in {@code proxy_connect}.
 */
public record ParentProxy(String host, int port) {

  /** Parses a {@code host:port} specification (supports bracketed IPv6 literals). */
  public static ParentProxy parse(String spec) {
    val uri = URI.create("tcp://" + spec.trim());
    val host = uri.getHost();
    val port = uri.getPort();
    if (!hasLength(host) || port <= 0 || port > 65535)
      throw new IllegalArgumentException("Invalid proxy spec: " + spec);
    return new ParentProxy(host, port);
  }

  @Override
  public @NonNull String toString() {
    return host + ":" + port;
  }
}
