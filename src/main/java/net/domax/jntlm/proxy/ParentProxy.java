package net.domax.jntlm.proxy;

/**
 * A parent proxy endpoint (host and port). DNS resolution is left to the socket layer at
 * connect time, mirroring CNTLM's lazy resolution in {@code proxy_connect}.
 */
public record ParentProxy(String host, int port) {

    /** Parses a {@code host:port} specification (supports bracketed IPv6 literals). */
    public static ParentProxy parse(String spec) {
        String s = spec.trim();
        String host;
        int port;
        if (s.startsWith("[")) {
            int close = s.indexOf(']');
            if (close < 0) {
                throw new IllegalArgumentException("Malformed IPv6 proxy spec: " + spec);
            }
            host = s.substring(1, close);
            int colon = s.indexOf(':', close);
            if (colon < 0) {
                throw new IllegalArgumentException("Missing port in proxy spec: " + spec);
            }
            port = Integer.parseInt(s.substring(colon + 1).trim());
        } else {
            int colon = s.lastIndexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException("Missing port in proxy spec: " + spec);
            }
            host = s.substring(0, colon);
            port = Integer.parseInt(s.substring(colon + 1).trim());
        }
        if (host.isEmpty() || port <= 0 || port > 65535) {
            throw new IllegalArgumentException("Invalid proxy spec: " + spec);
        }
        return new ParentProxy(host, port);
    }

    @Override
    public String toString() {
        return host + ":" + port;
    }
}
