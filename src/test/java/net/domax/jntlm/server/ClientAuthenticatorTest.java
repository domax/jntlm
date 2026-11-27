/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import lombok.val;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.proxy.Endpoint;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S5778")
class ClientAuthenticatorTest {

  private static JntlmProperties.User user(String name, String password) {
    val u = new JntlmProperties.User();
    u.setUsername(name);
    u.setPassword(password);
    return u;
  }

  private static JntlmProperties.ClientAuth config(JntlmProperties.User... users) {
    val c = new JntlmProperties.ClientAuth();
    c.setEnabled(true);
    c.setUsers(new ArrayList<>(List.of(users)));
    return c;
  }

  private static String sha256Hex(String s) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(UTF_8)));
  }

  private static HttpMessage request(String proxyAuthorization) {
    val r = HttpMessage.newRequest("GET", "http://example.com/", "HTTP/1.1");
    if (proxyAuthorization != null) r.getHeaders().add("Proxy-Authorization", proxyAuthorization);
    return r;
  }

  private static HttpMessage basic(String userPass) {
    return request("Basic " + Base64.getEncoder().encodeToString(userPass.getBytes(UTF_8)));
  }

  // ---------------------------------------------------------------- factories / validation

  @Test
  void disabledAcceptsEverything() {
    val a = ClientAuthenticator.disabled();
    assertFalse(a.enabled());
  }

  @Test
  void disabledConfigSkipsValidation() {
    val c = config(user("alice", ""));
    c.setEnabled(false);
    c.setRealm("");
    val a = assertDoesNotThrow(() -> ClientAuthenticator.from(c));
    assertFalse(a.enabled());
    assertFalse(ClientAuthenticator.from(new JntlmProperties.ClientAuth()).enabled());
  }

  @Test
  void rejectsEmptyUsers() {
    val ex = assertThrows(IllegalStateException.class, () -> ClientAuthenticator.from(config()));
    assertTrue(ex.getMessage().contains("at least one user"));
  }

  @Test
  void rejectsBlankUsername() {
    assertThrows(
        IllegalStateException.class, () -> ClientAuthenticator.from(config(user(" ", "pw"))));
  }

  @Test
  void rejectsUsernameWithColon() {
    assertThrows(
        IllegalStateException.class, () -> ClientAuthenticator.from(config(user("a:b", "pw"))));
  }

  @Test
  void rejectsBlankPassword() {
    val ex =
        assertThrows(
            IllegalStateException.class, () -> ClientAuthenticator.from(config(user("alice", ""))));
    assertTrue(ex.getMessage().contains("alice"));
  }

  @Test
  void rejectsMalformedDigestWithoutLeakingIt() {
    val ex =
        assertThrows(
            IllegalStateException.class,
            () -> ClientAuthenticator.from(config(user("bob", "{sha256}abc"))));
    assertTrue(ex.getMessage().contains("bob"));
    assertTrue(ex.getMessage().contains("digest"));
    assertFalse(ex.getMessage().contains("abc"));

    val nonHex = "{sha256}" + "z".repeat(64);
    assertThrows(
        IllegalStateException.class, () -> ClientAuthenticator.from(config(user("bob", nonHex))));
  }

  @Test
  void rejectsDuplicateUsername() {
    assertThrows(
        IllegalStateException.class,
        () -> ClientAuthenticator.from(config(user("alice", "a"), user("alice", "b"))));
  }

  @Test
  void rejectsInvalidRealm() {
    for (val realm : List.of(" ", "a\"b", "a\\b", "a\nb")) {
      val c = config(user("alice", "pw"));
      c.setRealm(realm);
      assertThrows(IllegalStateException.class, () -> ClientAuthenticator.from(c), realm);
    }
  }

  // ---------------------------------------------------------------- check

  @Test
  void plaintextPasswordMatches() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    assertTrue(a.enabled());
    assertEquals(1, a.userCount());
    val r = a.check(basic("alice:s3cret"));
    assertTrue(r.accepted());
    assertEquals("alice", r.username());
  }

  @Test
  void sha256PasswordMatchesCaseInsensitivePrefixAndHex() throws Exception {
    val hex = sha256Hex("pa:ss").toUpperCase(Locale.ROOT);
    val a =
        ClientAuthenticator.from(
            config(user("bob", "{sha256}" + hex), user("carol", "{SHA256}" + sha256Hex("x"))));
    assertTrue(a.check(basic("bob:pa:ss")).accepted());
    assertTrue(a.check(basic("carol:x")).accepted());
    assertFalse(a.check(basic("bob:pa")).accepted());
  }

  @Test
  void basicSchemeIsCaseInsensitive() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val enc = Base64.getEncoder().encodeToString("alice:s3cret".getBytes(UTF_8));
    assertTrue(a.check(request("BASIC " + enc)).accepted());
  }

  @Test
  void usernameIsCaseSensitive() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val r = a.check(basic("Alice:s3cret"));
    assertFalse(r.accepted());
    assertEquals("invalid credentials", r.reason());
  }

  @Test
  void wrongPasswordRejected() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val r = a.check(basic("alice:wrong"));
    assertFalse(r.accepted());
    assertEquals("invalid credentials", r.reason());
    assertEquals("alice", r.username());
  }

  @Test
  void unknownUserRejected() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    assertFalse(a.check(basic("mallory:s3cret")).accepted());
  }

  @Test
  void missingHeaderRejected() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val r = a.check(request(null));
    assertFalse(r.accepted());
    assertEquals("missing credentials", r.reason());
    assertNull(r.username());
  }

  @Test
  void ntlmSchemeRejected() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val r = a.check(request("NTLM TlRMTVNTUAABAAAA"));
    assertFalse(r.accepted());
    assertEquals("unsupported scheme", r.reason());
  }

  @Test
  void malformedBase64Rejected() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val r = a.check(request("Basic !!notbase64!!"));
    assertFalse(r.accepted());
    assertEquals("malformed credentials", r.reason());
  }

  @Test
  void missingColonRejected() {
    val a = ClientAuthenticator.from(config(user("alice", "s3cret")));
    val r = a.check(basic("alices3cret"));
    assertFalse(r.accepted());
    assertEquals("malformed credentials", r.reason());
  }

  // ---------------------------------------------------------------- sendChallenge

  @Test
  void sendChallengeWritesDefaultRealm() throws Exception {
    val out = challenge(ClientAuthenticator.from(config(user("alice", "pw"))), "HTTP/1.1");
    assertTrue(out.startsWith("HTTP/1.1 407 Proxy Authentication Required\r\n"), out);
    assertTrue(out.contains("\r\nProxy-Authenticate: Basic realm=\"jntlm\"\r\n"), out);
    assertTrue(out.contains("\r\nConnection: close\r\n"), out);
    assertTrue(out.contains("\r\nProxy-Connection: close\r\n"), out);

    val split = out.indexOf("\r\n\r\n");
    val body = out.substring(split + 4);
    val cl = out.lines().filter(l -> l.startsWith("Content-Length: ")).findFirst().orElseThrow();
    assertEquals(body.getBytes(ISO_8859_1).length, Integer.parseInt(cl.substring(16)));
  }

  @Test
  void sendChallengeUsesCustomRealmAndRequestProtocol() throws Exception {
    val c = config(user("alice", "pw"));
    c.setRealm("Corp Gateway");
    val out = challenge(ClientAuthenticator.from(c), "HTTP/1.0");
    assertTrue(out.startsWith("HTTP/1.0 407 "), out);
    assertTrue(out.contains("Proxy-Authenticate: Basic realm=\"Corp Gateway\"\r\n"), out);
  }

  /** Runs sendChallenge over a loopback socket pair and returns everything the peer received. */
  private static String challenge(ClientAuthenticator a, String protocol) throws Exception {
    try (val listener = new ServerSocket()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (val peer = new Socket()) {
        peer.connect(listener.getLocalSocketAddress());
        try (val server = listener.accept()) {
          val ep = new Endpoint(server);
          a.sendChallenge(ep, HttpMessage.newRequest("GET", "http://example.com/", protocol));
          ep.close();
          val buf = new ByteArrayOutputStream();
          peer.getInputStream().transferTo(buf);
          return buf.toString(ISO_8859_1);
        }
      }
    }
  }
}
