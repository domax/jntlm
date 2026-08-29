/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import lombok.val;

/**
 * An ordered, case-insensitive, multivalued collection of HTTP headers.
 *
 * <p>Mirrors the behaviour of CNTLM's {@code hlist_t}: header order is preserved, names are matched
 * case-insensitively, and duplicate header names are allowed. Provides the small set of operations
 * the proxy logic needs (add, replace/modify, delete, get, and token search).
 */
public final class HttpHeaders {

  /** A single header line, preserving the original name casing. */
  public record Header(String name, String value) {}

  private final List<Header> headers = new ArrayList<>();

  /** Appends a header, preserving order and allowing duplicates. */
  public void add(String name, String value) {
    headers.add(new Header(name, value));
  }

  /**
   * Adds or replaces a header (case-insensitive). If any header with this name exists, the first
   * occurrence is replaced and all further occurrences removed; otherwise it is appended. Mirrors
   * {@code hlist_mod(..., 1)}.
   */
  @SuppressWarnings("java:S127")
  public void modify(String name, String value) {
    boolean replaced = false;
    for (int i = 0; i < headers.size(); ++i) {
      if (headers.get(i).name().equalsIgnoreCase(name)) {
        if (!replaced) {
          headers.set(i, new Header(name, value));
          replaced = true;
        } else headers.remove(i--);
      }
    }
    if (!replaced) headers.add(new Header(name, value));
  }

  /** Removes all headers with the given name (case-insensitive). */
  public void remove(String name) {
    headers.removeIf(h -> h.name().equalsIgnoreCase(name));
  }

  /** Returns the value of the first header with the given name, or {@code null}. */
  public String getFirst(String name) {
    for (val h : headers) if (h.name().equalsIgnoreCase(name)) return h.value();
    return null;
  }

  /** Returns true if any header with the given name exists. */
  public boolean contains(String name) {
    return getFirst(name) != null;
  }

  /**
   * Returns true if any header with the given name has a value that contains {@code token} as a
   * case-insensitive substring. Mirrors {@code hlist_subcmp}.
   */
  public boolean containsToken(String name, String token) {
    val lower = token.toLowerCase(Locale.ROOT);
    return headers.stream()
        .anyMatch(
            h ->
                h.name().equalsIgnoreCase(name)
                    && h.value().toLowerCase(Locale.ROOT).contains(lower));
  }

  /** Returns the headers in order (live view; treat as read-only). */
  public List<Header> all() {
    return headers;
  }

  /** Returns a deep copy of these headers. */
  public HttpHeaders copy() {
    val c = new HttpHeaders();
    c.headers.addAll(this.headers);
    return c;
  }

  public boolean isEmpty() {
    return headers.isEmpty();
  }

  @Override
  public String toString() {
    return headers.toString();
  }
}
