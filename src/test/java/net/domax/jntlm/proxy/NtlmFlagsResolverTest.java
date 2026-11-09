/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.proxy.MockParentProxy.Received;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Tests for {@link NtlmFlagsResolver} against in-JVM {@link MockParentProxy} instances. */
class NtlmFlagsResolverTest {

  private static final long NTLMV2_DEFAULT = 0xa208b205L;
  private static final long[] ALL_NTLMV2_CANDIDATES = {
    0xa208b205L, 0x0008b205L, 0x00088205L, 0x00080205L, 0x00000205L
  };

  private final List<MockParentProxy> parents = new ArrayList<>();
  private MockParentProxy parent;
  private JntlmProperties props;
  private MutableClock clock;
  private ParentProxyManager manager;

  @BeforeEach
  void setUp() throws IOException {
    parent = newParent();
    props = new JntlmProperties();
    props.getCredentials().setUsername("testuser");
    props.getCredentials().setDomain("TESTDOMAIN");
    props.getCredentials().setPassword("SecREt01");
    props.getCredentials().setWorkstation("WS");
    clock = new MutableClock();
  }

  @AfterEach
  void tearDown() {
    parents.forEach(MockParentProxy::stop);
  }

  private MockParentProxy newParent() throws IOException {
    MockParentProxy p = new MockParentProxy();
    p.start();
    parents.add(p);
    return p;
  }

  private NtlmFlagsResolver resolver(MockParentProxy... ps) {
    List<String> list = new ArrayList<>();
    for (MockParentProxy p : ps.length == 0 ? new MockParentProxy[] {parent} : ps)
      list.add("127.0.0.1:" + p.port());
    props.setParents(list);
    manager = new ParentProxyManager(props, new ConnectionPool());
    return new NtlmFlagsResolver(manager, new JntlmConfig().globalCredentials(props), props, clock);
  }

  private static HttpMessage get(String url) {
    HttpMessage req = HttpMessage.newRequest("GET", url, "HTTP/1.1");
    req.setHost("example.com");
    req.setPort(80);
    req.getHeaders().add("Host", "example.com");
    return req;
  }

  // ------------------------------------------------------------------ 3.2 probe + templates

  @Test
  void probeAcceptsFullHandshake() {
    NtlmFlagsResolver.ProbeOutcome o = resolver().probe(NTLMV2_DEFAULT, get("http://example.com/"));
    assertTrue(o.accepted());
    assertEquals(1, parent.connectionsAccepted());
    assertEquals(List.of(1, 3), parent.received().stream().map(Received::ntlmType).toList());
  }

  @Test
  void probeRejectsMissingChallenge() {
    parent.rejectType1(NTLMV2_DEFAULT);
    NtlmFlagsResolver.ProbeOutcome o = resolver().probe(NTLMV2_DEFAULT, get("http://example.com/"));
    assertFalse(o.accepted());
    assertEquals("no challenge", o.reason());
  }

  @Test
  void probeRejectsType3AndReportsServerFlags() {
    parent.rejectType3(NTLMV2_DEFAULT).type2Flags(0x00088205L);
    NtlmFlagsResolver.ProbeOutcome o = resolver().probe(NTLMV2_DEFAULT, get("http://example.com/"));
    assertFalse(o.accepted());
    assertEquals(0x00088205L, o.serverFlags());
  }

  @Test
  void probeAcceptsWhenNoAuthRequired() {
    parent.requireAuth(false);
    NtlmFlagsResolver.ProbeOutcome o = resolver().probe(NTLMV2_DEFAULT, get("http://example.com/"));
    assertTrue(o.accepted());
    assertEquals(1, parent.received().size());
  }

  @Test
  void lazyTemplateTurnsPostIntoBodylessGet() {
    HttpMessage post = HttpMessage.newRequest("POST", "http://example.com/api", "HTTP/1.1");
    post.getHeaders().add("Host", "example.com");
    post.getHeaders().add("Content-Length", "5");
    post.getHeaders().add("Content-Type", "text/plain");
    post.getHeaders().add("Proxy-Authorization", "Basic xyz");
    HttpMessage t = NtlmFlagsResolver.lazyTemplate(post);
    assertEquals("GET", t.getMethod());
    assertEquals("http://example.com/api", t.getUrl());
    assertFalse(t.getHeaders().contains("Content-Length"));
    assertFalse(t.getHeaders().contains("Content-Type"));
    assertFalse(t.getHeaders().contains("Proxy-Authorization"));
    assertEquals("POST", post.getMethod(), "original request must not be mutated");
  }

  @Test
  void lazyTemplateTurnsHeadIntoGet() {
    HttpMessage head = HttpMessage.newRequest("HEAD", "http://example.com/", "HTTP/1.1");
    assertEquals("GET", NtlmFlagsResolver.lazyTemplate(head).getMethod());
  }

  @Test
  void lazyTemplateKeepsConnect() {
    HttpMessage connect = HttpMessage.newRequest("CONNECT", "example.com:443", "HTTP/1.1");
    HttpMessage t = NtlmFlagsResolver.lazyTemplate(connect);
    assertEquals("CONNECT", t.getMethod());
    assertEquals("example.com:443", t.getUrl());
  }

  @Test
  void eagerTemplateForHttp() {
    HttpMessage t = NtlmFlagsResolver.eagerTemplate(URI.create("http://example.com/"));
    assertEquals("GET", t.getMethod());
    assertEquals("http://example.com/", t.getUrl());
    assertEquals("example.com", t.getHeaders().getFirst("Host"));
    assertEquals(80, t.getPort());
  }

  @Test
  void eagerTemplateForHttps() {
    HttpMessage t = NtlmFlagsResolver.eagerTemplate(URI.create("https://example.com/"));
    assertEquals("CONNECT", t.getMethod());
    assertEquals("example.com:443", t.getUrl());
    assertEquals(
        "example.com:8443",
        NtlmFlagsResolver.eagerTemplate(URI.create("https://example.com:8443")).getUrl());
  }

  @SuppressWarnings("java:S5778")
  @Test
  void eagerTemplateRejectsUnsupportedScheme() {
    assertThrows(
        IllegalArgumentException.class,
        () -> NtlmFlagsResolver.eagerTemplate(URI.create("ftp://x.com/")));
  }

  // ------------------------------------------------------------------ 3.3 detection

  @Test
  void explicitFlagsAcceptedFirst() {
    props.setFlags("0x00088205");
    NtlmFlagsResolver.Resolved r = resolver().detect(get("http://example.com/"));
    assertEquals(0x00088205L, r.flags());
    assertTrue(r.detected());
    assertEquals(List.of(0x00088205L), parent.type1Flags());
  }

  @Test
  void defaultAccepted() {
    NtlmFlagsResolver.Resolved r = resolver().detect(get("http://example.com/"));
    assertEquals(NTLMV2_DEFAULT, r.flags());
    assertEquals(List.of(NTLMV2_DEFAULT), parent.type1Flags());
  }

  @Test
  void reducedVariantReached() {
    parent.rejectType1(0xa208b205L, 0x0008b205L, 0x00080205L, 0x00000205L);
    NtlmFlagsResolver.Resolved r = resolver().detect(get("http://example.com/"));
    assertEquals(0x00088205L, r.flags());
    assertEquals(List.of(0xa208b205L, 0x0008b205L, 0x00088205L), parent.type1Flags());
  }

  @Test
  void challengeDerivedCandidateTriedNext() {
    parent.rejectType3(NTLMV2_DEFAULT).type2Flags(0x00088205L);
    NtlmFlagsResolver.Resolved r = resolver().detect(get("http://example.com/"));
    assertEquals(0x00088205L, r.flags());
    assertEquals(List.of(NTLMV2_DEFAULT, 0x00088205L), parent.type1Flags());
  }

  @Test
  void allRejectedFallsBackToDefault() {
    parent.rejectType1(ALL_NTLMV2_CANDIDATES);
    NtlmFlagsResolver.Resolved r = resolver().detect(get("http://example.com/"));
    assertEquals(NTLMV2_DEFAULT, r.flags());
    assertFalse(r.detected());
    assertEquals(ALL_NTLMV2_CANDIDATES.length, parent.type1Flags().size());
  }

  @Test
  void explicitRejectedFallsBackToDefault() {
    props.setFlags("0x00000205");
    parent.rejectType1(ALL_NTLMV2_CANDIDATES);
    NtlmFlagsResolver.Resolved r = resolver().detect(get("http://example.com/"));
    assertEquals(NTLMV2_DEFAULT, r.flags());
    assertFalse(r.detected());
  }

  // ------------------------------------------------------------------ 3.4 cache + single-flight

  @Test
  void secondCallUsesCache() {
    NtlmFlagsResolver resolver = resolver();
    assertEquals(NTLMV2_DEFAULT, resolver.flagsFor(get("http://example.com/")));
    assertEquals(NTLMV2_DEFAULT, resolver.flagsFor(get("http://example.com/")));
    assertEquals(1, parent.type1Flags().size());
  }

  @Test
  void concurrentCallsDetectOnce() throws Exception {
    parent.challengeDelayMs(300);
    NtlmFlagsResolver resolver = resolver();
    AtomicLong a = new AtomicLong();
    AtomicLong b = new AtomicLong();
    Thread t1 = Thread.ofVirtual().start(() -> a.set(resolver.flagsFor(get("http://x/"))));
    Thread t2 = Thread.ofVirtual().start(() -> b.set(resolver.flagsFor(get("http://y/"))));
    t1.join(5000);
    t2.join(5000);
    assertEquals(NTLMV2_DEFAULT, a.get());
    assertEquals(NTLMV2_DEFAULT, b.get());
    assertEquals(1, parent.type1Flags().size());
  }

  @Test
  void disabledReturnsExplicitWithoutProbing() {
    props.getDetect().setEnabled(false);
    props.setFlags("0x00088205");
    assertEquals(0x00088205L, resolver().flagsFor(get("http://example.com/")));
    assertEquals(0, parent.connectionsAccepted());
  }

  @Test
  void disabledReturnsDefaultWithoutExplicit() {
    props.getDetect().setEnabled(false);
    assertEquals(NTLMV2_DEFAULT, resolver().flagsFor(get("http://example.com/")));
    assertEquals(0, parent.connectionsAccepted());
  }

  // ------------------------------------------------------------------ 3.5 invalidation

  @Test
  void rejectionAfterCooldownTriggersRedetection() {
    NtlmFlagsResolver resolver = resolver();
    long flags = resolver.flagsFor(get("http://example.com/"));
    clock.advance(NtlmFlagsResolver.COOLDOWN.plusSeconds(1));
    resolver.reportRejected(flags);
    resolver.flagsFor(get("http://example.com/"));
    assertEquals(2, parent.type1Flags().size());
  }

  @Test
  void rejectionWithinCooldownKeepsCache() {
    NtlmFlagsResolver resolver = resolver();
    long flags = resolver.flagsFor(get("http://example.com/"));
    clock.advance(Duration.ofSeconds(10));
    resolver.reportRejected(flags);
    resolver.flagsFor(get("http://example.com/"));
    assertEquals(1, parent.type1Flags().size());
  }

  @Test
  void rejectionOfOtherFlagsIgnored() {
    NtlmFlagsResolver resolver = resolver();
    resolver.flagsFor(get("http://example.com/"));
    clock.advance(NtlmFlagsResolver.COOLDOWN.plusSeconds(1));
    resolver.reportRejected(0x1234L);
    resolver.flagsFor(get("http://example.com/"));
    assertEquals(1, parent.type1Flags().size());
  }

  @Test
  void parentSwitchTriggersRedetection() throws Exception {
    MockParentProxy second = newParent();
    NtlmFlagsResolver resolver = resolver(parent, second);
    resolver.flagsFor(get("http://example.com/"));
    assertEquals(1, parent.type1Flags().size());

    parent.stop();
    manager.connect().close(); // fails over to the second parent
    assertEquals("127.0.0.1", manager.activeParent().host());
    assertEquals(second.port(), manager.activeParent().port());

    resolver.flagsFor(get("http://example.com/"));
    assertEquals(1, second.type1Flags().size());
  }

  // ------------------------------------------------------------------ 3.6 eager detection

  @Test
  void eagerDetectionPopulatesCache() throws Exception {
    props.getDetect().setProbeUrl(URI.create("http://probe.example.com/"));
    NtlmFlagsResolver resolver = resolver();
    Thread t = resolver.startEagerDetection();
    t.join(5000);
    assertEquals("GET", parent.received().getFirst().method());
    assertEquals("http://probe.example.com/", parent.received().getFirst().url());

    assertEquals(NTLMV2_DEFAULT, resolver.flagsFor(get("http://example.com/")));
    assertEquals(1, parent.type1Flags().size());
  }

  @Test
  void eagerDetectionSkippedWhenNotConfigured() {
    assertNull(resolver().startEagerDetection());
    props.getDetect().setProbeUrl(URI.create("http://probe.example.com/"));
    props.getDetect().setEnabled(false);
    assertNull(resolver().startEagerDetection());
    assertEquals(0, parent.connectionsAccepted());
  }

  /** A {@link Clock} whose instant can be advanced by tests. */
  private static final class MutableClock extends Clock {
    private Instant now = Instant.parse("2026-01-01T00:00:00Z");

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
