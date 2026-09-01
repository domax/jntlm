/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Tests for {@link ParentProxy} parsing, accessors and string representation. */
class ParentProxyTest {

  @Test
  void parsesHostAndPort() {
    ParentProxy p = ParentProxy.parse("proxy.example.com:8080");
    assertEquals("proxy.example.com", p.host());
    assertEquals(8080, p.port());
  }

  @Test
  void parsesIpv4() {
    ParentProxy p = ParentProxy.parse("10.0.0.1:3128");
    assertEquals("10.0.0.1", p.host());
    assertEquals(3128, p.port());
  }

  @Test
  void parsesBracketedIpv6() {
    ParentProxy p = ParentProxy.parse("[2001:db8::1]:8080");
    assertEquals("[2001:db8::1]", p.host());
    assertEquals(8080, p.port());
  }

  @Test
  void trimsSurroundingWhitespace() {
    ParentProxy p = ParentProxy.parse("  proxy:8080  ");
    assertEquals("proxy", p.host());
    assertEquals(8080, p.port());
  }

  @Test
  void trimsWhitespaceAroundPort() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("proxy: 8080 "));
  }

  @Test
  void hostWithoutPortThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("proxy.example.com"));
  }

  @Test
  void ipv6WithoutPortThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("[2001:db8::1]"));
  }

  @Test
  void malformedIpv6Throws() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("[2001:db8::1:8080"));
  }

  @Test
  void emptyHostThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse(":8080"));
  }

  @Test
  void nonNumericPortThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("proxy:abc"));
  }

  @Test
  void zeroPortThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("proxy:0"));
  }

  @Test
  void negativePortThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("proxy:-1"));
  }

  @Test
  void portAboveRangeThrows() {
    assertThrows(IllegalArgumentException.class, () -> ParentProxy.parse("proxy:65536"));
  }

  @Test
  void maxPortIsAccepted() {
    ParentProxy p = ParentProxy.parse("proxy:65535");
    assertEquals(65535, p.port());
  }

  @Test
  void toStringRendersHostColonPort() {
    assertEquals("proxy.example.com:8080", ParentProxy.parse("proxy.example.com:8080").toString());
    assertEquals("2001:db8::1:8080", new ParentProxy("2001:db8::1", 8080).toString());
  }

  @Test
  void recordEqualityAndAccessors() {
    ParentProxy a = new ParentProxy("host", 80);
    ParentProxy b = new ParentProxy("host", 80);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertEquals("host", a.host());
    assertEquals(80, a.port());
  }
}
