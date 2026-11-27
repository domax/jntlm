/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Generates minimal HTML error pages, mirroring CNTLM's {@code pages.c}. */
public final class ErrorPages {

  private static final String EOL = "\r\n";

  private ErrorPages() {}

  /**
   * Writes a "502 Bad Gateway" style page (parent proxy unreachable). Ports {@code gen_502_page}.
   */
  static void send502(OutputStream out, String http) throws IOException {
    send(out, 502, "jntlm proxy failed to complete the request.", http);
  }

  /**
   * Writes a minimal error page with {@code Connection: close}. Not in CNTLM: also used for the
   * strict-framing and resource-limit replies (400, 431, 503, 504).
   *
   * @param out the client output stream
   * @param status the HTTP status code
   * @param detail a short human-readable explanation for the page body
   * @param http the client's protocol (e.g. {@code HTTP/1.1}); {@code null} means {@code HTTP/1.0}
   */
  public static void send(OutputStream out, int status, String detail, String http)
      throws IOException {
    String proto = (http == null || http.isBlank()) ? "HTTP/1.0" : http;
    String title = status + " " + reason(status);
    String body =
        "<html><body>" + "<h1>" + title + "</h1>" + "<p>" + detail + "</p>" + "</body></html>";
    String response =
        proto
            + " "
            + title
            + EOL
            + "Content-Type: text/html"
            + EOL
            + "Content-Length: "
            + body.getBytes(StandardCharsets.ISO_8859_1).length
            + EOL
            + "Connection: close"
            + EOL
            + EOL
            + body;
    out.write(response.getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
  }

  /** Returns the standard reason phrase for the statuses jntlm generates. */
  static String reason(int status) {
    return switch (status) {
      case 400 -> "Bad Request";
      case 407 -> "Proxy Authentication Required";
      case 431 -> "Request Header Fields Too Large";
      case 502 -> "Bad Gateway";
      case 503 -> "Service Unavailable";
      case 504 -> "Gateway Timeout";
      default -> "Error";
    };
  }
}
