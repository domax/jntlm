/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static java.util.Optional.ofNullable;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import lombok.NoArgsConstructor;
import lombok.val;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * An ordered, case-insensitive, multivalued collection of HTTP headers.
 *
 * <p>Mirrors the behavior of CNTLM's {@code hlist_t}: header order is preserved, names are matched
 * case-insensitively, and duplicate header names are allowed. Provides the small set of operations
 * the proxy logic needs (add, replace/modify, delete, get, and token search).
 */
@NoArgsConstructor
@NullMarked
public final class HttpHeaders {

  private record InnerHeader(String name, Set<String> values) {

    InnerHeader copy() {
      return new InnerHeader(name, new LinkedHashSet<>(values));
    }
  }

  /** A single header line, preserving the original name casing. */
  public record Header(String name, String value) {

    @Override
    public String toString() {
      return name + "=" + value;
    }
  }

  private final Map<String, InnerHeader> headers = new LinkedHashMap<>();

  private HttpHeaders(Map<String, InnerHeader> headers) {
    this.headers.putAll(headers);
  }

  private static String getKey(String name) {
    return name.toLowerCase(Locale.ROOT);
  }

  /** Appends a header, preserving order and allowing duplicates. */
  public void add(String name, String value) {
    val key = getKey(name);
    val header = headers.get(key);
    if (header != null) header.values.add(value);
    else headers.put(key, new InnerHeader(name, new LinkedHashSet<>(Set.of(value))));
  }

  /**
   * Adds or replaces a header (case-insensitive). If any header with this name exists, the first
   * occurrence is replaced and all further occurrences removed; otherwise it is appended. Mirrors
   * {@code hlist_mod(..., 1)}.
   */
  public void modify(String name, String value) {
    val key = getKey(name);
    val header = headers.get(key);
    if (header != null) {
      header.values.clear();
      header.values.add(value);
    } else headers.put(key, new InnerHeader(name, new LinkedHashSet<>(Set.of(value))));
  }

  /** Removes all headers with the given name (case-insensitive). */
  public void remove(String name) {
    headers.remove(getKey(name));
  }

  /** Returns the value of the first header with the given name, or {@code null}. */
  @Nullable public String getFirst(String name) {
    return ofNullable(headers.get(getKey(name))).stream()
        .flatMap(h -> h.values.stream())
        .findFirst()
        .orElse(null);
  }

  /** Returns true if any header with the given name exists. */
  public boolean contains(String name) {
    return headers.containsKey(getKey(name));
  }

  /**
   * Returns true if any header with the given name has a value that contains {@code token} as a
   * case-insensitive substring. Mirrors {@code hlist_subcmp}.
   */
  public boolean containsToken(String name, String token) {
    val lower = token.toLowerCase(Locale.ROOT);
    return ofNullable(headers.get(getKey(name))).stream()
        .flatMap(h -> h.values.stream())
        .anyMatch(v -> v.toLowerCase(Locale.ROOT).contains(lower));
  }

  /** Returns the copy of headers in order. */
  public List<Header> all() {
    return headers.values().stream()
        .flatMap(h -> h.values.stream().map(v -> new Header(h.name, v)))
        .toList();
  }

  /** Returns a deep copy of these headers. */
  public HttpHeaders copy() {
    val copy =
        this.headers.entrySet().stream()
            .map(e -> Map.entry(e.getKey(), e.getValue().copy()))
            .collect(
                LinkedHashMap<String, InnerHeader>::new,
                (m, e) -> m.put(e.getKey(), e.getValue()),
                Map::putAll);
    return new HttpHeaders(copy);
  }

  /** Returns true if there are no headers. */
  public boolean isEmpty() {
    return headers.isEmpty();
  }

  @Override
  public String toString() {
    return all().toString();
  }
}
