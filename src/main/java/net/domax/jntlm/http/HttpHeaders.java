/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import lombok.NoArgsConstructor;
import lombok.val;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * An ordered, case-insensitive, multivalued collection of HTTP headers.
 *
 * <p>Mirrors the behavior of CNTLM's {@code hlist_t}: every field line is kept in received order
 * (including repeated names with identical values), names are matched case-insensitively, and
 * duplicate header names are allowed. Messages carry tens of headers, so lookups are linear scans
 * over a list. Provides the small set of operations the proxy logic needs (add, replace/modify,
 * delete, get, and token search).
 */
@NoArgsConstructor
@NullMarked
public final class HttpHeaders {

  /** A single header line, preserving the original name casing. */
  public record Header(String name, String value) {

    @Override
    public String toString() {
      return name + "=" + value;
    }
  }

  private final List<Header> entries = new ArrayList<>();

  private HttpHeaders(List<Header> entries) {
    this.entries.addAll(entries);
  }

  /** Appends a header, preserving order and allowing duplicates. */
  public void add(String name, String value) {
    entries.add(new Header(name, value));
  }

  /**
   * Adds or replaces a header (case-insensitive). If any header with this name exists, the first
   * occurrence is replaced in place and all further occurrences removed; otherwise it is appended.
   * Mirrors {@code hlist_mod(..., 1)}.
   */
  public void modify(String name, String value) {
    var replaced = false;
    for (var it = entries.listIterator(); it.hasNext(); ) {
      val h = it.next();
      if (!h.name().equalsIgnoreCase(name)) continue;
      if (replaced) it.remove();
      else {
        it.set(new Header(h.name(), value));
        replaced = true;
      }
    }
    if (!replaced) add(name, value);
  }

  /** Removes all headers with the given name (case-insensitive). */
  public void remove(String name) {
    entries.removeIf(h -> h.name().equalsIgnoreCase(name));
  }

  /** Returns the value of the first header with the given name, or {@code null}. */
  @Nullable public String getFirst(String name) {
    for (val h : entries) if (h.name().equalsIgnoreCase(name)) return h.value();
    return null;
  }

  /** Returns the values of all headers with the given name, in order. */
  public List<String> getAll(String name) {
    val result = new ArrayList<String>(2);
    for (val h : entries) if (h.name().equalsIgnoreCase(name)) result.add(h.value());
    return result;
  }

  /** Returns true if any header with the given name exists. */
  public boolean contains(String name) {
    for (val h : entries) if (h.name().equalsIgnoreCase(name)) return true;
    return false;
  }

  /**
   * Returns true if any header with the given name has a comma-separated element equal to {@code
   * token} (case-insensitive, surrounding whitespace ignored).
   *
   * <p>Not in CNTLM: {@code hlist_subcmp} is a substring match, which makes {@code Connection:
   * notclose} count as {@code close}; jntlm matches whole tokens.
   */
  public boolean containsToken(String name, String token) {
    for (val h : entries)
      if (h.name().equalsIgnoreCase(name))
        for (val element : h.value().split(","))
          if (element.trim().equalsIgnoreCase(token)) return true;
    return false;
  }

  /**
   * Returns the last comma-separated element over all headers with the given name (lower-cased,
   * trimmed), or {@code null} if there is none. Used for the final {@code Transfer-Encoding}.
   */
  @Nullable String lastToken(String name) {
    String last = null;
    for (val h : entries)
      if (h.name().equalsIgnoreCase(name))
        for (val element : h.value().split(",")) {
          val t = element.trim();
          if (!t.isEmpty()) last = t.toLowerCase(Locale.ROOT);
        }
    return last;
  }

  /** Returns the copy of headers in order. */
  public List<Header> all() {
    return List.copyOf(entries);
  }

  /** Appends all headers directly to a wire-format builder without creating snapshot objects. */
  public void appendTo(StringBuilder target) {
    for (val h : entries) target.append(h.name()).append(": ").append(h.value()).append("\r\n");
  }

  /** Returns a deep copy of these headers. */
  public HttpHeaders copy() {
    return new HttpHeaders(entries);
  }

  /** Returns true if there are no headers. */
  public boolean isEmpty() {
    return entries.isEmpty();
  }

  /** Returns the number of header lines. */
  public int size() {
    return entries.size();
  }

  @Override
  public String toString() {
    return entries.toString();
  }
}
