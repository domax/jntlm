/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import lombok.Data;
import lombok.val;

/**
 * An HTTP request or response message (request/status line + headers), analogous to CNTLM's {@code
 * rr_data_t}.
 *
 * <p>A message is either a request (has {@link #method}, {@link #url}) or a response (has {@link
 * #code}, {@link #status}). The HTTP version is stored as an integer, e.g. {@code 11} for {@code
 * HTTP/1.1}, matching CNTLM's {@code http_version} convention.
 */
@Data
public final class HttpMessage {

  private boolean request;

  // Request line
  private String method;
  private String url;

  // Response line
  private int code;
  private String status;

  // Common
  private String protocol = "HTTP/1.1";
  private int httpVersion = 11;

  private final HttpHeaders headers = new HttpHeaders();

  // Parsed connection target (for absolute request URLs / CONNECT authority)
  private String host;
  private int port;

  public static HttpMessage newRequest(String method, String url, String protocol) {
    val m = new HttpMessage();
    m.request = true;
    m.method = method;
    m.url = url;
    m.setProtocol(protocol);
    return m;
  }

  public static HttpMessage newResponse(String protocol, int code, String status) {
    val m = new HttpMessage();
    m.request = false;
    m.setProtocol(protocol);
    m.code = code;
    m.status = status;
    return m;
  }

  public boolean isResponse() {
    return !request;
  }

  public boolean isConnect() {
    return request && "CONNECT".equalsIgnoreCase(method);
  }

  public boolean isHead() {
    return request && "HEAD".equalsIgnoreCase(method);
  }

  /** Sets the protocol string (e.g. {@code HTTP/1.1}) and derives {@link #httpVersion}. */
  public void setProtocol(String protocol) {
    this.protocol = protocol;
    this.httpVersion = parseVersion(protocol);
  }

  /** Renders the request or status line (without trailing CRLF). */
  public String startLine() {
    if (request) return method + " " + url + " " + protocol;
    return protocol + " " + code + " " + (status == null ? "" : status);
  }

  private static int parseVersion(String protocol) {
    if (protocol == null) return 10;

    int slash = protocol.indexOf('/');
    if (slash < 0) return 10;

    val v = protocol.substring(slash + 1).trim();
    val dot = v.indexOf('.');
    try {
      if (dot < 0) return Integer.parseInt(v) * 10;

      val major = Integer.parseInt(v.substring(0, dot));
      val minor = Integer.parseInt(v.substring(dot + 1));
      return major * 10 + minor;
    } catch (NumberFormatException e) {
      return 10;
    }
  }

  /** Returns a deep copy of this message (headers included). */
  public HttpMessage copy() {
    val m = new HttpMessage();
    m.request = this.request;
    m.method = this.method;
    m.url = this.url;
    m.code = this.code;
    m.status = this.status;
    m.protocol = this.protocol;
    m.httpVersion = this.httpVersion;
    m.host = this.host;
    m.port = this.port;
    for (val h : this.headers.all()) m.headers.add(h.name(), h.value());
    return m;
  }

  @Override
  public String toString() {
    return startLine() + " " + headers;
  }
}
