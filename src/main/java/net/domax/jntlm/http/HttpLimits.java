/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

/**
 * Bounds applied while reading a header section (start line, header lines, chunked trailers). Not
 * in CNTLM.
 *
 * @param maxHeaderBytes maximum total bytes of the header section, line terminators included
 * @param maxHeaderCount maximum number of header (or trailer) lines
 */
public record HttpLimits(int maxHeaderBytes, int maxHeaderCount) {

  /** Defaults matching {@code jntlm.limits.*}. */
  public static final HttpLimits DEFAULT = new HttpLimits(131072, 256);
}
