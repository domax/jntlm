/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static java.util.Optional.ofNullable;
import static java.util.function.Predicate.not;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

/**
 * HTTP wire-format I/O: reading and writing message headers and bodies, plus CONNECT tunnelling.
 * Ports the relevant functions of CNTLM's {@code http.c} ({@code headers_recv}, {@code
 * headers_send}, {@code http_has_body}, {@code http_body_send}, {@code http_body_drop}, {@code
 * chunked_data_send}, {@code tunnel}).
 */
@Slf4j
public final class HttpIo {

  private static final int BUFSIZE = 8192;
  private static final int MAX_LINE_LENGTH = 64 * 1024;
  private static final String EOL = "\r\n";

  private static final String TRANSFER_ENCODING = "Transfer-Encoding";
  private static final String CONTENT_LENGTH = "Content-Length";

  private static final String TOKEN_CHUNKED = "chunked";
  private static final byte[] CRLF_BYTES = {'\r', '\n'};

  private static final int SC_BAD_REQUEST = 400;
  private static final int SC_TOO_LARGE = 431;
  private static final int SC_BAD_GATEWAY = 502;

  private static final Pattern HTTP_VERSION = Pattern.compile("HTTP/\\d\\.\\d");
  private static final Pattern STATUS_CODE = Pattern.compile("\\d{3}");
  private static final Pattern CONTENT_LENGTH_VALUE = Pattern.compile("\\d{1,18}");
  private static final Pattern PORT = Pattern.compile("\\d{1,5}");

  /** Special {@link #httpHasBody} return meaning "chunked transfer-encoding". */
  static final long CHUNKED = 1;

  /** Special {@link #httpHasBody} return meaning "read until connection close". */
  static final long UNTIL_CLOSE = -1;

  private HttpIo() {}

  // ---------------------------------------------------------------- headers

  /**
   * Reads a message using {@link HttpLimits#DEFAULT}. See {@link #recvHeaders(InputStream,
   * HttpLimits)}.
   */
  public static HttpMessage recvHeaders(InputStream in) throws IOException {
    return recvHeaders(in, HttpLimits.DEFAULT);
  }

  /**
   * Reads a request or status line plus all headers from the stream. Ports {@code headers_recv}.
   *
   * <p>Returns {@code null} only on a clean EOF before the first byte (CNTLM returning &le; 0). Not
   * in CNTLM: the parser is strict and bounded &mdash; a malformed start line, obs-fold, whitespace
   * before the colon, a missing colon, a non-token field name, a bare CR, an invalid or conflicting
   * {@code Content-Length}, a request with {@code Transfer-Encoding} plus {@code Content-Length} or
   * a non-{@code chunked} final coding, or a request without a usable host all raise {@link
   * HttpProtocolException} ({@code 400} for requests, {@code 502} for responses); exceeding {@code
   * limits} raises {@code 431} (requests and unknown start lines) or {@code 502} (responses). A
   * header section truncated by EOF raises {@link EOFException}.
   */
  @SuppressWarnings({"java:S3776", "java:S135"})
  public static HttpMessage recvHeaders(InputStream in, HttpLimits limits) throws IOException {
    var budget = limits.maxHeaderBytes();
    var raw = readLine(in, Math.min(MAX_LINE_LENGTH, budget), SC_TOO_LARGE, SC_BAD_REQUEST);
    if (raw == null) return null;
    // RFC 9112 section 2.2: ignore empty lines received before the request-line.
    while (stripEol(raw).isEmpty()) {
      budget -= raw.length();
      raw = readLine(in, Math.min(MAX_LINE_LENGTH, budget), SC_TOO_LARGE, SC_BAD_REQUEST);
      if (raw == null) return null;
    }
    budget -= raw.length();
    val line = stripEol(raw);

    final HttpMessage msg;
    String host = null;
    if (line.regionMatches(true, 0, "HTTP/", 0, 5)) msg = parseStatusLine(line);
    else {
      msg = parseRequestLine(line);
      host = extractHost(msg.getUrl());
    }

    val malformed = msg.isRequest() ? SC_BAD_REQUEST : SC_BAD_GATEWAY;
    val overLimit = msg.isRequest() ? SC_TOO_LARGE : SC_BAD_GATEWAY;
    readFieldLines(in, msg.getHeaders(), limits.maxHeaderCount(), budget, overLimit, malformed);

    validateFraming(msg, malformed);

    if (msg.isRequest()) {
      if (host == null || host.isEmpty()) host = msg.getHeaders().getFirst("Host");
      if (host == null || host.isBlank())
        throw new HttpProtocolException(SC_BAD_REQUEST, "missing Host");
      if (msg.getHeaders().getFirst("Host") == null) msg.getHeaders().add("Host", host);
      parseHostPort(msg, host.trim());
    }

    return msg;
  }

  /** Writes the start line, all headers and the terminating blank line. */
  public static void sendHeaders(OutputStream out, HttpMessage msg) throws IOException {
    val sb = new StringBuilder();
    sb.append(msg.startLine()).append(EOL);
    msg.getHeaders().appendTo(sb);
    sb.append(EOL);
    out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
  }

  private static HttpMessage parseStatusLine(String line) throws HttpProtocolException {
    val parts = line.split(" ", 3);
    if (parts.length < 2
        || !HTTP_VERSION.matcher(parts[0]).matches()
        || !STATUS_CODE.matcher(parts[1]).matches())
      throw new HttpProtocolException(SC_BAD_GATEWAY, "malformed status line");
    return HttpMessage.newResponse(
        parts[0], Integer.parseInt(parts[1]), parts.length >= 3 ? parts[2] : "");
  }

  private static HttpMessage parseRequestLine(String line) throws HttpProtocolException {
    val parts = line.split(" ", -1);
    if (parts.length != 3
        || !isToken(parts[0])
        || parts[1].isEmpty()
        || !HTTP_VERSION.matcher(parts[2]).matches())
      throw new HttpProtocolException(SC_BAD_REQUEST, "malformed request line");
    return HttpMessage.newRequest(parts[0], parts[1], parts[2]);
  }

  /**
   * Reads field lines (headers or chunked trailers) up to the terminating blank line into {@code
   * target} (if not {@code null}), returning the raw bytes read. Enforces the line count and the
   * remaining byte budget.
   */
  @SuppressWarnings("java:S3776")
  private static String readFieldLines(
      InputStream in, HttpHeaders target, int maxCount, int budget, int overLimit, int malformed)
      throws IOException {
    val raw = new StringBuilder();
    var count = 0;
    while (true) {
      if (budget <= 0) throw new HttpProtocolException(overLimit, "header section too large");
      val h = readLine(in, Math.min(MAX_LINE_LENGTH, budget), overLimit, malformed);
      if (h == null) throw new EOFException("EOF inside header section");
      budget -= h.length();
      raw.append(h);

      val field = stripEol(h);
      if (field.isEmpty()) return raw.toString();
      if (++count > maxCount) throw new HttpProtocolException(overLimit, "too many header fields");

      if (field.charAt(0) == ' ' || field.charAt(0) == '\t')
        throw new HttpProtocolException(malformed, "obsolete line folding");
      val colon = field.indexOf(':');
      if (colon <= 0) throw new HttpProtocolException(malformed, "header line without name/colon");
      val name = field.substring(0, colon);
      if (!isToken(name)) throw new HttpProtocolException(malformed, "invalid header field name");
      if (target != null) target.add(name, trimOws(field.substring(colon + 1)));
    }
  }

  /**
   * Validates and normalizes {@code Content-Length}/{@code Transfer-Encoding} (RFC 9112 section 6).
   * Not in CNTLM.
   */
  @SuppressWarnings("java:S3776")
  private static void validateFraming(HttpMessage msg, int malformed) throws HttpProtocolException {
    val headers = msg.getHeaders();
    val cls = headers.getAll(CONTENT_LENGTH);
    String cl = null;
    for (val value : cls)
      for (val element : value.split(",", -1)) {
        val v = trimOws(element);
        if (!CONTENT_LENGTH_VALUE.matcher(v).matches())
          throw new HttpProtocolException(malformed, "invalid Content-Length");
        if (cl == null) cl = v;
        else if (!cl.equals(v))
          throw new HttpProtocolException(malformed, "conflicting Content-Length");
      }
    if (cl != null && (cls.size() > 1 || !cls.getFirst().equals(cl)))
      headers.modify(CONTENT_LENGTH, cl);

    if (!headers.contains(TRANSFER_ENCODING)) return;
    val chunked = isChunked(msg);
    if (msg.isRequest()) {
      if (cl != null)
        throw new HttpProtocolException(SC_BAD_REQUEST, "Transfer-Encoding with Content-Length");
      if (!chunked)
        throw new HttpProtocolException(SC_BAD_REQUEST, "final transfer-coding is not chunked");
    } else {
      if (cl != null) {
        headers.remove(CONTENT_LENGTH);
        msg.setReusable(false);
      }
      if (!chunked) msg.setReusable(false);
    }
  }

  // ---------------------------------------------------------------- bodies

  /**
   * Returns true if the message is chunked, i.e. the final transfer-coding over all {@code
   * Transfer-Encoding} fields is {@code chunked}. Not in CNTLM: {@code hlist_subcmp} substring
   * match would also accept e.g. {@code xchunked}.
   */
  public static boolean isChunked(HttpMessage msg) {
    return TOKEN_CHUNKED.equals(msg.getHeaders().lastToken(TRANSFER_ENCODING));
  }

  /**
   * Determines the body length for the current message. Ports {@code http_has_body}. Pass {@code
   * response == null} to evaluate the request body only.
   *
   * <p>Not in CNTLM: a request body is determined solely by {@code Transfer-Encoding}/{@code
   * Content-Length} for every method ({@code http_has_body} ignores GET/HEAD bodies, which would
   * desynchronize the connection). Response rules are unchanged.
   *
   * @return {@code 0} = no HTTP body, {@link #UNTIL_CLOSE} = until close, {@link #CHUNKED} =
   *     chunked, otherwise the explicit Content-Length.
   */
  @SuppressWarnings("java:S3776")
  public static long httpHasBody(HttpMessage request, HttpMessage response) {
    val current = (response == null) ? request : response;
    if (current == null) return 0;

    val headers = current.getHeaders();
    val cl = headers.getFirst(CONTENT_LENGTH);
    if (current == request) {
      if (isChunked(request)) return CHUNKED;
      return cl == null ? 0 : parseLong(cl);
    }

    if (isNoBody(request, response)) return 0;
    if (cl == null
        && (headers.contains("Content-Type")
            || headers.contains(TRANSFER_ENCODING)
            || headers.containsToken("Connection", "close")))
      return isChunked(response) ? CHUNKED : UNTIL_CLOSE;
    return cl == null ? 0 : parseLong(cl);
  }

  private static boolean isNoBody(HttpMessage request, HttpMessage response) {
    val code = response.getCode();
    return (request != null && request.isHead())
        || (code >= 100 && code < 200)
        || code == 204
        || code == 304;
  }

  /**
   * Returns true if the response is delimited without relying on connection close: it carries no
   * body by definition, has a {@code Content-Length}, is chunked, or is a successful CONNECT. Not
   * in CNTLM; used to decide whether a parent connection may be pooled.
   */
  public static boolean isCleanlyFramed(HttpMessage request, HttpMessage response) {
    if (!response.isReusable()) return false;
    if (request != null && request.isConnect() && response.getCode() / 100 == 2) return true;
    if (isNoBody(request, response)) return true;
    return isChunked(response) || response.getHeaders().contains(CONTENT_LENGTH);
  }

  /**
   * Forwards the HTTP body (if any) from {@code in} to {@code out}. Ports {@code http_body_send}.
   */
  public static void sendBody(
      OutputStream out, InputStream in, HttpMessage request, HttpMessage response)
      throws IOException {
    sendBody(out, in, request, response, HttpLimits.DEFAULT);
  }

  /**
   * As {@link #sendBody(OutputStream, InputStream, HttpMessage, HttpMessage)}, bounding trailers.
   */
  public static void sendBody(
      OutputStream out,
      InputStream in,
      HttpMessage request,
      HttpMessage response,
      HttpLimits limits)
      throws IOException {
    val current = (response == null) ? request : response;
    val bodyLen = httpHasBody(request, response);
    if (bodyLen == 0) return;

    try {
      if (isChunked(current)) chunkedTransfer(out, in, limits);
      else dataTransfer(out, in, bodyLen);
    } catch (IOException e) {
      // Relay whatever was already read before the exchange is aborted.
      try {
        out.flush();
      } catch (IOException suppressed) {
        e.addSuppressed(suppressed);
      }
      throw e;
    }
    out.flush();
  }

  /** Reads and discards the body of a response. Ports {@code http_body_drop}. */
  public static void dropBody(InputStream in, HttpMessage response) throws IOException {
    dropBody(in, response, HttpLimits.DEFAULT);
  }

  /** As {@link #dropBody(InputStream, HttpMessage)}, bounding trailers. */
  public static void dropBody(InputStream in, HttpMessage response, HttpLimits limits)
      throws IOException {
    val bodyLen = httpHasBody(null, response);
    if (bodyLen == 0) return;

    if (isChunked(response)) chunkedTransfer(null, in, limits);
    else dataTransfer(null, in, bodyLen);
  }

  /**
   * Copies {@code length} bytes from {@code in} to {@code out}. If {@code length} is negative,
   * copies until EOF. If {@code out} is {@code null}, the data is discarded. Ports {@code
   * data_send}. Not in CNTLM: EOF before {@code length} bytes raises {@link EOFException}.
   */
  static void dataTransfer(OutputStream out, InputStream in, long length) throws IOException {
    val buf = new byte[BUFSIZE];
    long remaining = length;
    while (length < 0 || remaining > 0) {
      val toRead = (length < 0) ? buf.length : (int) Math.min(buf.length, remaining);
      val r = in.read(buf, 0, toRead);
      if (r < 0) {
        if (length < 0) break;
        throw new EOFException("EOF with " + remaining + " body bytes outstanding");
      }

      if (out != null && r > 0) out.write(buf, 0, r);
      if (length >= 0) remaining -= r;
    }
  }

  /**
   * Forwards a chunked-encoded body from {@code in} to {@code out} (or discards it if {@code out}
   * is {@code null}). Ports {@code chunked_data_send}.
   *
   * <p>Not in CNTLM: a chunk-size line must be 1&ndash;16 hex digits optionally followed by
   * whitespace and {@code ;extensions}; each chunk's data must be followed by exactly CRLF;
   * trailers are bounded by {@code limits}; any violation raises {@link HttpProtocolException} and
   * premature EOF raises {@link EOFException}.
   */
  @SuppressWarnings("java:S3776")
  static void chunkedTransfer(OutputStream out, InputStream in, HttpLimits limits)
      throws IOException {
    long csize;
    do {
      val sizeLine = readLine(in, MAX_LINE_LENGTH, SC_BAD_REQUEST, SC_BAD_REQUEST);
      if (sizeLine == null) throw new EOFException("EOF before chunk size");
      csize = parseChunkSize(stripEol(sizeLine));

      if (out != null) out.write(sizeLine.getBytes(StandardCharsets.ISO_8859_1));
      if (csize > 0) {
        dataTransfer(out, in, csize);
        val cr = in.read();
        val lf = cr == '\r' ? in.read() : cr;
        if (cr < 0 || lf < 0) throw new EOFException("EOF after chunk data");
        if (cr != '\r' || lf != '\n')
          throw new HttpProtocolException(SC_BAD_REQUEST, "chunk data not followed by CRLF");
        if (out != null) out.write(CRLF_BYTES);
      }
    } while (csize != 0);

    // Forward the (usually empty) trailer up to the terminating blank line.
    val trailer =
        readFieldLines(
            in,
            null,
            limits.maxHeaderCount(),
            limits.maxHeaderBytes(),
            SC_BAD_REQUEST,
            SC_BAD_REQUEST);
    if (out != null) {
      out.write(trailer.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
    }
  }

  private static long parseChunkSize(String line) throws HttpProtocolException {
    var i = 0;
    while (i < line.length() && Character.digit(line.charAt(i), 16) >= 0) i++;
    if (i == 0 || i > 16) throw new HttpProtocolException(SC_BAD_REQUEST, "invalid chunk size");
    var j = i;
    while (j < line.length() && (line.charAt(j) == ' ' || line.charAt(j) == '\t')) j++;
    if (j < line.length() && line.charAt(j) != ';')
      throw new HttpProtocolException(SC_BAD_REQUEST, "invalid chunk size");
    val size = Long.parseUnsignedLong(line, 0, i, 16);
    if (size < 0) throw new HttpProtocolException(SC_BAD_REQUEST, "chunk size too large");
    return size;
  }

  // ---------------------------------------------------------------- tunnel

  /**
   * Full-duplex byte relay between two connections until either side closes. Ports {@code tunnel}.
   * Used to bridge an established CONNECT tunnel. Operates on the (possibly buffered) streams so
   * that no already-read bytes are lost, and closes both sockets when done.
   */
  public static void tunnel(
      InputStream clientIn,
      OutputStream clientOut,
      Socket clientSocket,
      InputStream serverIn,
      OutputStream serverOut,
      Socket serverSocket) {
    tunnel(clientIn, clientOut, clientSocket, serverIn, serverOut, serverSocket, Duration.ZERO);
  }

  /**
   * As {@link #tunnel(InputStream, OutputStream, Socket, InputStream, OutputStream, Socket)}, but
   * closes both sockets once no byte has moved in either direction for {@code idleTimeout}. Not in
   * CNTLM. A zero timeout disables the check (both sockets block indefinitely, replacing any
   * client-idle or parent-read timeout for the tunnel's lifetime).
   */
  public static void tunnel(
      InputStream clientIn,
      OutputStream clientOut,
      Socket clientSocket,
      InputStream serverIn,
      OutputStream serverOut,
      Socket serverSocket,
      Duration idleTimeout) {
    val idleMs = idleTimeout == null || idleTimeout.isNegative() ? 0L : idleTimeout.toMillis();
    val soTimeout = (int) Math.min(idleMs, Integer.MAX_VALUE);
    try {
      clientSocket.setSoTimeout(soTimeout);
      serverSocket.setSoTimeout(soTimeout);
    } catch (SocketException e) {
      closeQuietly(clientSocket);
      closeQuietly(serverSocket);
      return;
    }
    val lastActivity = new AtomicLong(System.nanoTime());
    val pump =
        Thread.ofVirtual()
            .start(
                () -> pump(clientIn, serverOut, clientSocket, serverSocket, idleMs, lastActivity));
    try {
      pump(serverIn, clientOut, clientSocket, serverSocket, idleMs, lastActivity);
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

  @SuppressWarnings({"java:S135", "java:S1141"})
  private static void pump(
      InputStream in, OutputStream out, Socket a, Socket b, long idleMs, AtomicLong lastActivity) {
    val buf = new byte[BUFSIZE];
    try {
      while (true) {
        final int r;
        try {
          r = in.read(buf);
        } catch (SocketTimeoutException e) {
          // Only give up when the *whole* tunnel (both directions) has been idle long enough.
          if (System.nanoTime() - lastActivity.get() >= idleMs * 1_000_000L) {
            log.debug("Closing CONNECT tunnel idle for {} ms", idleMs);
            break;
          }
          continue;
        }
        if (r <= 0) break;
        lastActivity.set(System.nanoTime());
        out.write(buf, 0, r);
        out.flush();
      }
    } catch (SocketException se) {
      ofNullable(se.getMessage())
          .filter(not(String::isBlank))
          .ifPresentOrElse(
              msg -> {
                if ("Socket closed".equals(msg)) log.debug("Socket closed in tunnel pump");
                else log.error("Socket error in tunnel pump: {}", msg);
              },
              () -> log.error("Socket error in tunnel pump"));
    } catch (Exception e) {
      log.error("Error in tunnel pump: {}", e.toString());
    } finally {
      closeQuietly(a);
      closeQuietly(b);
    }
  }

  // ---------------------------------------------------------------- helpers

  /**
   * Reads a single line terminated by LF, keeping the terminator. Returns {@code null} on EOF
   * before any byte; raises {@link EOFException} on EOF mid-line, {@code overLimit} when longer
   * than {@code max} bytes, and {@code malformed} on a CR not immediately followed by LF.
   */
  private static String readLine(InputStream in, int max, int overLimit, int malformed)
      throws IOException {
    val baos = new ByteArrayOutputStream(128);
    int c;
    while ((c = in.read()) != -1) {
      if (baos.size() >= max) throw new HttpProtocolException(overLimit, "line too long");
      baos.write(c);
      if (c == '\n') break;
    }
    if (baos.size() == 0) return null;
    if (c != '\n') throw new EOFException("EOF inside line");

    val bytes = baos.toByteArray();
    val crAllowedAt = bytes.length >= 2 && bytes[bytes.length - 2] == '\r' ? bytes.length - 2 : -1;
    for (var i = 0; i < bytes.length - 1; i++)
      if (bytes[i] == '\r' && i != crAllowedAt)
        throw new HttpProtocolException(malformed, "bare CR");
    return new String(bytes, StandardCharsets.ISO_8859_1);
  }

  private static String stripEol(String s) {
    var end = s.length();
    if (end > 0 && s.charAt(end - 1) == '\n') end--;
    if (end > 0 && s.charAt(end - 1) == '\r') end--;
    return s.substring(0, end);
  }

  private static String trimOws(String s) {
    var b = 0;
    var e = s.length();
    while (b < e && (s.charAt(b) == ' ' || s.charAt(b) == '\t')) b++;
    while (e > b && (s.charAt(e - 1) == ' ' || s.charAt(e - 1) == '\t')) e--;
    return s.substring(b, e);
  }

  /** RFC 9110 {@code token}. */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private static boolean isToken(String s) {
    if (s.isEmpty()) return false;
    for (var i = 0; i < s.length(); i++) {
      val c = s.charAt(i);
      if (c > 0x7e || (!Character.isLetterOrDigit(c) && "!#$%&'*+-.^_`|~".indexOf(c) < 0))
        return false;
    }
    return true;
  }

  /** Extracts the authority ("host[:port]") from a request-target URL. */
  private static String extractHost(String url) {
    var scheme = url.indexOf("://");
    val rest = scheme >= 0 ? url.substring(scheme + 3) : url;
    var slash = rest.indexOf('/');
    return slash >= 0 ? rest.substring(0, slash) : rest;
  }

  /**
   * Parses "host[:port]" (incl. bracketed IPv6) into the message, defaulting the port. Not in
   * CNTLM: an empty host or a port outside 1&ndash;65535 raises {@code 400}.
   */
  @SuppressWarnings("java:S3776")
  private static void parseHostPort(HttpMessage msg, String host) throws HttpProtocolException {
    final String hostname;
    String port = null;
    if (host.startsWith("[")) {
      val close = host.indexOf(']');
      if (close < 0) throw new HttpProtocolException(SC_BAD_REQUEST, "invalid host");
      hostname = host.substring(1, close);
      if (close + 1 < host.length()) {
        if (host.charAt(close + 1) != ':')
          throw new HttpProtocolException(SC_BAD_REQUEST, "invalid host");
        port = host.substring(close + 2);
      }
    } else {
      val colon = host.lastIndexOf(':');
      if (colon >= 0) {
        hostname = host.substring(0, colon);
        port = host.substring(colon + 1);
      } else hostname = host;
    }
    if (hostname.isEmpty()) throw new HttpProtocolException(SC_BAD_REQUEST, "empty host");

    int portNum;
    if (port == null || port.isEmpty())
      portNum =
          msg.getUrl() != null && msg.getUrl().regionMatches(true, 0, "https", 0, 5) ? 443 : 80;
    else {
      portNum = PORT.matcher(port).matches() ? Integer.parseInt(port) : 0;
      if (portNum < 1 || portNum > 65535)
        throw new HttpProtocolException(SC_BAD_REQUEST, "invalid port");
    }

    msg.setHost(hostname);
    msg.setPort(portNum);
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
      if (!s.isClosed()) s.close();
    } catch (IOException ignored) {
      // ignore
    }
  }
}
