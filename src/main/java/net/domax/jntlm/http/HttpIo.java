package net.domax.jntlm.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * HTTP wire-format I/O: reading and writing message headers and bodies, plus CONNECT
 * tunnelling. Ports the relevant functions of CNTLM's {@code http.c}
 * ({@code headers_recv}, {@code headers_send}, {@code http_has_body}, {@code http_body_send},
 * {@code http_body_drop}, {@code chunked_data_send}, {@code tunnel}).
 */
public final class HttpIo {

    private static final int BUFSIZE = 8192;
    /** Special {@link #httpHasBody} return meaning "chunked transfer-encoding". */
    static final long CHUNKED = 1;
    /** Special {@link #httpHasBody} return meaning "read until connection close". */
    static final long UNTIL_CLOSE = -1;

    private HttpIo() {
    }

    // ---------------------------------------------------------------- headers

    /**
     * Reads a request or status line plus all headers from the stream. Returns {@code null}
     * on EOF or a malformed start line (mirrors CNTLM returning &le; 0 from {@code headers_recv}).
     */
    public static HttpMessage recvHeaders(InputStream in) throws IOException {
        String line = readLine(in);
        if (line == null) {
            return null;
        }
        line = trimTrailing(line);

        HttpMessage msg;
        String host = null;

        String[] parts = line.split(" ", 3);
        if (parts.length >= 1 && parts[0].regionMatches(true, 0, "HTTP/", 0, 5)) {
            // Response
            if (parts.length < 2) {
                return null;
            }
            String proto = parts[0];
            int code;
            try {
                code = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                return null;
            }
            String status = parts.length >= 3 ? parts[2] : "";
            msg = HttpMessage.newResponse(proto, code, status);
        } else if (line.contains(" HTTP/") && parts.length == 3) {
            // Request
            String method = parts[0];
            String url = parts[1];
            String proto = parts[2];
            msg = HttpMessage.newRequest(method, url, proto);
            host = extractHost(url);
        } else {
            return null;
        }

        // Read header lines until a blank line.
        while (true) {
            String h = readLine(in);
            if (h == null) {
                break;
            }
            h = trimTrailing(h);
            if (h.isEmpty()) {
                break;
            }
            int colon = h.indexOf(':');
            if (colon > 0) {
                String name = h.substring(0, colon).trim();
                String value = h.substring(colon + 1).trim();
                msg.getHeaders().add(name, value);
            }
        }

        if (msg.isRequest()) {
            if (host == null || host.isEmpty()) {
                host = msg.getHeaders().getFirst("Host");
            }
            if (host == null || host.isEmpty()) {
                return null;
            }
            if (msg.getHeaders().getFirst("Host") == null) {
                msg.getHeaders().add("Host", host);
            }
            parseHostPort(msg, host);
            if (msg.getHost() == null || msg.getHost().isEmpty() || msg.getPort() == 0) {
                return null;
            }
        }

        return msg;
    }

    /** Writes the start line, all headers and the terminating blank line. */
    public static void sendHeaders(OutputStream out, HttpMessage msg) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(msg.startLine()).append("\r\n");
        for (HttpHeaders.Header h : msg.getHeaders().all()) {
            sb.append(h.name()).append(": ").append(h.value()).append("\r\n");
        }
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    // ---------------------------------------------------------------- bodies

    /**
     * Determines the body length for the current message. Ports {@code http_has_body}.
     * Pass {@code response == null} to evaluate the request body only.
     *
     * @return {@code 0} = no body, {@link #UNTIL_CLOSE} = until close, {@link #CHUNKED} = chunked,
     *         otherwise the explicit Content-Length.
     */
    public static long httpHasBody(HttpMessage request, HttpMessage response) {
        HttpMessage current = (response == null) ? request : response;
        if (current == null) {
            return 0;
        }

        boolean nobody;
        if (current == response) {
            int code = response.getCode();
            nobody = (request != null && request.isHead())
                    || (code >= 100 && code < 200)
                    || code == 204
                    || code == 304;
        } else {
            boolean get = request != null && "GET".equalsIgnoreCase(request.getMethod());
            nobody = get || (request != null && request.isHead());
        }

        HttpHeaders headers = current.getHeaders();
        String cl = headers.getFirst("Content-Length");
        long length;
        if (!nobody && cl == null
                && (headers.contains("Content-Type")
                    || headers.contains("Transfer-Encoding")
                    || headers.containsToken("Connection", "close"))) {
            if (headers.contains("Transfer-Encoding")
                    && headers.containsToken("Transfer-Encoding", "chunked")) {
                length = CHUNKED;
            } else {
                length = UNTIL_CLOSE;
            }
        } else {
            length = (cl == null || nobody) ? 0 : parseLong(cl);
        }

        if (current == request && length == UNTIL_CLOSE) {
            length = 0;
        }
        return length;
    }

    /** Forwards the HTTP body (if any) from {@code in} to {@code out}. Ports {@code http_body_send}. */
    public static void sendBody(OutputStream out, InputStream in, HttpMessage request, HttpMessage response)
            throws IOException {
        HttpMessage current = (response == null) ? request : response;
        long bodylen = httpHasBody(request, response);
        if (bodylen == 0) {
            return;
        }
        if (current.getHeaders().containsToken("Transfer-Encoding", "chunked")) {
            chunkedTransfer(out, in);
        } else {
            dataTransfer(out, in, bodylen);
        }
    }

    /** Reads and discards the body of a response. Ports {@code http_body_drop}. */
    public static void dropBody(InputStream in, HttpMessage response) throws IOException {
        long bodylen = httpHasBody(null, response);
        if (bodylen == 0) {
            return;
        }
        if (response.getHeaders().containsToken("Transfer-Encoding", "chunked")) {
            chunkedTransfer(null, in);
        } else {
            dataTransfer(null, in, bodylen);
        }
    }

    /**
     * Copies {@code length} bytes from {@code in} to {@code out}. If {@code length} is negative,
     * copies until EOF. If {@code out} is {@code null}, the data is discarded. Ports {@code data_send}.
     */
    static void dataTransfer(OutputStream out, InputStream in, long length) throws IOException {
        byte[] buf = new byte[BUFSIZE];
        long remaining = length;
        while (length < 0 || remaining > 0) {
            int toRead = (length < 0) ? buf.length : (int) Math.min(buf.length, remaining);
            int r = in.read(buf, 0, toRead);
            if (r < 0) {
                break;
            }
            if (out != null && r > 0) {
                out.write(buf, 0, r);
            }
            if (length >= 0) {
                remaining -= r;
            }
        }
        if (out != null) {
            out.flush();
        }
    }

    /**
     * Forwards a chunked-encoded body from {@code in} to {@code out} (or discards it if
     * {@code out} is {@code null}). Ports {@code chunked_data_send}.
     */
    static void chunkedTransfer(OutputStream out, InputStream in) throws IOException {
        int csize;
        do {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                return;
            }
            String hex = sizeLine.trim();
            int semi = hex.indexOf(';');
            if (semi >= 0) {
                hex = hex.substring(0, semi).trim();
            }
            if (hex.isEmpty()) {
                return;
            }
            try {
                csize = Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                return;
            }
            if (out != null) {
                out.write(sizeLine.getBytes(StandardCharsets.ISO_8859_1));
            }
            if (csize > 0) {
                dataTransfer(out, in, (long) csize + 2);
            }
        } while (csize != 0);

        // Forward the (usually empty) trailer up to the terminating blank line.
        String trailer;
        do {
            trailer = readLine(in);
            if (trailer != null && out != null) {
                out.write(trailer.getBytes(StandardCharsets.ISO_8859_1));
            }
        } while (trailer != null && !trailer.isEmpty()
                && trailer.charAt(0) != '\r' && trailer.charAt(0) != '\n');

        if (out != null) {
            out.flush();
        }
    }

    // ---------------------------------------------------------------- tunnel

    /**
     * Full-duplex byte relay between two connections until either side closes. Ports {@code tunnel}.
     * Used to bridge an established CONNECT tunnel. Operates on the (possibly buffered) streams so
     * that no already-read bytes are lost, and closes both sockets when done.
     */
    public static void tunnel(InputStream clientIn, OutputStream clientOut, Socket clientSocket,
                              InputStream serverIn, OutputStream serverOut, Socket serverSocket)
            throws IOException {
        Thread pump = Thread.ofVirtual().start(
                () -> pump(clientIn, clientOut, clientSocket, serverSocket));
        try {
            pump(serverIn, serverOut, clientSocket, serverSocket);
        } finally {
            closeQuietly(clientSocket);
            closeQuietly(serverSocket);
            try {
                pump.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void pump(InputStream in, OutputStream out, Socket a, Socket b) {
        byte[] buf = new byte[BUFSIZE];
        try {
            int r;
            while ((r = in.read(buf)) > 0) {
                out.write(buf, 0, r);
                out.flush();
            }
        } catch (IOException ignored) {
            // connection closed - fall through to close both sides
        } finally {
            closeQuietly(a);
            closeQuietly(b);
        }
    }

    // ---------------------------------------------------------------- helpers

    /** Reads a single line terminated by LF, keeping the trailing CRLF. Returns null at EOF. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(128);
        int c;
        boolean any = false;
        while ((c = in.read()) != -1) {
            any = true;
            baos.write(c);
            if (c == '\n') {
                break;
            }
        }
        if (!any) {
            return null;
        }
        return baos.toString(StandardCharsets.ISO_8859_1);
    }

    private static String trimTrailing(String s) {
        int end = s.length();
        while (end > 0 && (s.charAt(end - 1) == '\r' || s.charAt(end - 1) == '\n')) {
            end--;
        }
        return s.substring(0, end);
    }

    /** Extracts the authority ("host[:port]") from a request-target URL. */
    private static String extractHost(String url) {
        int scheme = url.indexOf("://");
        String rest = scheme >= 0 ? url.substring(scheme + 3) : url;
        int slash = rest.indexOf('/');
        return slash >= 0 ? rest.substring(0, slash) : rest;
    }

    /** Parses "host[:port]" (incl. bracketed IPv6) into the message, defaulting the port. */
    private static void parseHostPort(HttpMessage msg, String host) {
        String hostname;
        int port = 0;
        if (host.startsWith("[")) {
            int close = host.indexOf(']');
            hostname = host.substring(1, close < 0 ? host.length() : close);
            if (close >= 0 && close + 1 < host.length() && host.charAt(close + 1) == ':') {
                port = parseInt(host.substring(close + 2));
            }
        } else {
            int colon = host.indexOf(':');
            if (colon >= 0) {
                hostname = host.substring(0, colon);
                port = parseInt(host.substring(colon + 1));
            } else {
                hostname = host;
            }
        }
        if (port == 0) {
            port = (msg.getUrl() != null && msg.getUrl().regionMatches(true, 0, "https", 0, 5)) ? 443 : 80;
        }
        msg.setHost(hostname);
        msg.setPort(port);
    }

    private static int parseInt(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            if (!s.isClosed()) {
                s.close();
            }
        } catch (IOException ignored) {
            // ignore
        }
    }
}
