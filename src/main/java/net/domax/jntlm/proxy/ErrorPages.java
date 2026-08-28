/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Generates minimal HTML error pages, mirroring CNTLM's {@code pages.c}. */
final class ErrorPages {

  private ErrorPages() {}

  /**
   * Writes a "502 Bad Gateway" style page (parent proxy unreachable). Ports {@code gen_502_page}.
   */
  static void send502(OutputStream out, String http, String message) throws IOException {
    String proto = (http == null || http.isBlank()) ? "HTTP/1.0" : http;
    String body =
        "<html><body><h1>502 "
            + message
            + "</h1><p>jntlm proxy failed to complete "
            + "the request.</p></body></html>";
    String response =
        proto
            + " 502 "
            + message
            + "\r\n"
            + "Content-Type: text/html\r\n"
            + "Content-Length: "
            + body.getBytes(StandardCharsets.ISO_8859_1).length
            + "\r\n"
            + "Connection: close\r\n\r\n"
            + body;
    out.write(response.getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
  }
}
