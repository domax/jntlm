/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
  public void modify(String name, String value) {
    boolean replaced = false;
    for (int i = 0; i < headers.size(); ) {
      if (headers.get(i).name().equalsIgnoreCase(name)) {
        if (!replaced) {
          headers.set(i, new Header(name, value));
          replaced = true;
          i++;
        } else {
          headers.remove(i);
        }
      } else {
        i++;
      }
    }
    if (!replaced) {
      headers.add(new Header(name, value));
    }
  }

  /** Removes all headers with the given name (case-insensitive). */
  public void remove(String name) {
    headers.removeIf(h -> h.name().equalsIgnoreCase(name));
  }

  /** Returns the value of the first header with the given name, or {@code null}. */
  public String getFirst(String name) {
    for (Header h : headers) {
      if (h.name().equalsIgnoreCase(name)) {
        return h.value();
      }
    }
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
    String lower = token.toLowerCase(Locale.ROOT);
    for (Header h : headers) {
      if (h.name().equalsIgnoreCase(name) && h.value().toLowerCase(Locale.ROOT).contains(lower)) {
        return true;
      }
    }
    return false;
  }

  /** Returns the headers in order (live view; treat as read-only). */
  public List<Header> all() {
    return headers;
  }

  /** Returns a deep copy of these headers. */
  public HttpHeaders copy() {
    HttpHeaders c = new HttpHeaders();
    c.headers.addAll(this.headers);
    return c;
  }

  public boolean isEmpty() {
    return headers.isEmpty();
  }
}
