/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Tests for {@link HttpHeaders#copy()} deep-copy semantics. */
class HttpHeadersTest {

  @Test
  void copyProducesEqualIndependentSnapshot() {
    HttpHeaders original = new HttpHeaders();
    original.add("Content-Type", "text/html");
    original.add("Set-Cookie", "a=1");
    original.add("set-cookie", "b=2");

    HttpHeaders copy = original.copy();

    assertEquals(original.all(), copy.all());
  }

  @Test
  void copyPreservesOrderAndCasing() {
    HttpHeaders original = new HttpHeaders();
    original.add("X-First", "1");
    original.add("X-Second", "2");
    original.add("X-Third", "3");

    List<HttpHeaders.Header> copied = original.copy().all();

    assertEquals(
        List.of("X-First", "X-Second", "X-Third"),
        copied.stream().map(HttpHeaders.Header::name).toList());
    assertEquals(List.of("1", "2", "3"), copied.stream().map(HttpHeaders.Header::value).toList());
  }

  @Test
  void mutatingCopyDoesNotAffectOriginal() {
    HttpHeaders original = new HttpHeaders();
    original.add("Connection", "keep-alive");
    original.add("Set-Cookie", "a=1");

    HttpHeaders copy = original.copy();
    copy.modify("Connection", "close");
    copy.add("Set-Cookie", "b=2");
    copy.remove("Set-Cookie");
    copy.add("X-New", "new");

    assertEquals("keep-alive", original.getFirst("Connection"));
    assertEquals("a=1", original.getFirst("Set-Cookie"));
    assertTrue(original.contains("Set-Cookie"));
    assertFalse(original.contains("X-New"));
  }

  @Test
  void mutatingOriginalDoesNotAffectCopy() {
    HttpHeaders original = new HttpHeaders();
    original.add("Connection", "keep-alive");

    HttpHeaders copy = original.copy();
    original.modify("Connection", "close");
    original.add("X-Added", "1");

    assertEquals("keep-alive", copy.getFirst("Connection"));
    assertFalse(copy.contains("X-Added"));
  }

  @Test
  void copyOfEmptyIsEmpty() {
    assertTrue(new HttpHeaders().copy().isEmpty());
  }
}
