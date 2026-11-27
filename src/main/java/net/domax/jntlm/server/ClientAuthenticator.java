/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.val;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.proxy.Endpoint;
import org.jspecify.annotations.Nullable;

/**
 * Optional HTTP BASIC proxy authentication of clients connecting to the jntlm listener.
 *
 * <p>Not in CNTLM: this is a jntlm-only feature with no CNTLM counterpart (CNTLM's {@code
 * NTLMToBasic} passes client credentials to the parent, which is a different behavior). Configured
 * passwords (plaintext or {@code {sha256}<hex>}) are normalized to SHA-256 digests at startup and
 * compared in constant time; plaintext passwords are not retained.
 */
@Getter
@Accessors(fluent = true)
public final class ClientAuthenticator {

  private static final String PROXY_AUTHORIZATION = "Proxy-Authorization";
  private static final String SHA256_PREFIX = "{sha256}";
  private static final String BASIC_PREFIX = "basic ";
  private static final byte[] DUMMY_DIGEST = sha256("jntlm-dummy-password");

  /** Outcome of {@link #check(HttpMessage)}. */
  public record Result(boolean accepted, @Nullable String reason, @Nullable String username) {

    static Result ok(String username) {
      return new Result(true, null, username);
    }

    static Result reject(String reason, @Nullable String username) {
      return new Result(false, reason, username);
    }
  }

  private final boolean enabled;
  private final String realm;
  private final Map<String, byte[]> users;

  private ClientAuthenticator(boolean enabled, String realm, Map<String, byte[]> users) {
    this.enabled = enabled;
    this.realm = realm;
    this.users = users;
  }

  /** Returns an authenticator that accepts every client without checking credentials. */
  public static ClientAuthenticator disabled() {
    return new ClientAuthenticator(false, "", Map.of());
  }

  /**
   * Builds an authenticator from configuration. Returns {@link #disabled()} when not enabled (no
   * validation); otherwise validates the configuration.
   *
   * @throws IllegalStateException if the enabled configuration is invalid
   */
  @SuppressWarnings("java:S3776")
  public static ClientAuthenticator from(JntlmProperties.ClientAuth config) {
    if (config == null || !config.isEnabled()) return disabled();

    val realm = config.getRealm();
    if (realm == null || realm.isBlank())
      throw invalid("jntlm.client-auth.realm must not be blank");
    if (realm.chars().anyMatch(c -> c == '"' || c == '\\' || Character.isISOControl(c)))
      throw invalid("jntlm.client-auth.realm must not contain '\"', '\\' or control characters");

    List<JntlmProperties.User> list = config.getUsers();
    if (list == null || list.isEmpty())
      throw invalid("jntlm.client-auth.users: at least one user is required when enabled");

    val users = new HashMap<String, byte[]>();
    for (int i = 0; i < list.size(); i++) {
      val u = list.get(i);
      val name = u == null ? null : u.getUsername();
      if (name == null || name.isBlank())
        throw invalid("jntlm.client-auth.users[" + i + "].username must not be blank");
      if (name.indexOf(':') >= 0)
        throw invalid("jntlm.client-auth.users[" + i + "].username must not contain ':'");
      if (users.containsKey(name))
        throw invalid("jntlm.client-auth.users: duplicate username '" + name + "'");
      users.put(name, digestOf(name, u.getPassword()));
    }
    return new ClientAuthenticator(true, realm, Map.copyOf(users));
  }

  /** Normalizes a configured password (plaintext or {@code {sha256}<hex>}) to an SHA-256 digest. */
  private static byte[] digestOf(String user, @Nullable String password) {
    if (password == null || password.isBlank())
      throw invalid("jntlm.client-auth: password for user '" + user + "' must not be blank");
    if (!password.regionMatches(true, 0, SHA256_PREFIX, 0, SHA256_PREFIX.length()))
      return sha256(password);

    val hex = password.substring(SHA256_PREFIX.length()).trim();
    try {
      if (hex.length() != 64) throw new IllegalArgumentException();
      return HexFormat.of().parseHex(hex.toLowerCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw invalid("jntlm.client-auth: password digest for user '" + user + "' is invalid");
    }
  }

  /** Number of configured users. */
  public int userCount() {
    return users.size();
  }

  /** Verifies the BASIC {@code Proxy-Authorization} credentials carried by {@code request}. */
  public Result check(HttpMessage request) {
    val header = request.getHeaders().getFirst(PROXY_AUTHORIZATION);
    if (header == null || header.isBlank()) return Result.reject("missing credentials", null);

    val value = header.trim();
    if (!value.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length()))
      return Result.reject("unsupported scheme", null);

    final String decoded;
    try {
      decoded =
          new String(
              Base64.getDecoder().decode(value.substring(BASIC_PREFIX.length()).trim()), UTF_8);
    } catch (IllegalArgumentException e) {
      return Result.reject("malformed credentials", null);
    }
    val colon = decoded.indexOf(':');
    if (colon < 0) return Result.reject("malformed credentials", null);

    val name = decoded.substring(0, colon);
    val given = sha256(decoded.substring(colon + 1));
    val expected = users.get(name);
    // Always compare (against a dummy for unknown users) to keep timing uniform.
    val match = MessageDigest.isEqual(given, expected != null ? expected : DUMMY_DIGEST);
    return expected != null && match ? Result.ok(name) : Result.reject("invalid credentials", name);
  }

  /**
   * Writes a {@code 407 Proxy Authentication Required} reply with a BASIC challenge and {@code
   * Connection: close}. The request body (if any) is not read; the caller must close the
   * connection.
   */
  public void sendChallenge(Endpoint client, HttpMessage request) throws IOException {
    val proto =
        request == null || request.getProtocol() == null || request.getProtocol().isBlank()
            ? "HTTP/1.1"
            : request.getProtocol();
    val body =
        "<html><body><h1>407 Proxy Authentication Required</h1>"
            + "<p>jntlm proxy requires authentication.</p></body></html>";
    val bytes = body.getBytes(ISO_8859_1);

    val reply = HttpMessage.newResponse(proto, 407, "Proxy Authentication Required");
    val h = reply.getHeaders();
    h.add("Proxy-Authenticate", "Basic realm=\"" + realm + "\"");
    h.add("Content-Type", "text/html");
    h.add("Content-Length", Integer.toString(bytes.length));
    h.add("Connection", "close");
    h.add("Proxy-Connection", "close");

    val out = client.out();
    HttpIo.sendHeaders(out, reply);
    out.write(bytes);
    out.flush();
  }

  private static byte[] sha256(String s) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(s.getBytes(UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }

  private static IllegalStateException invalid(String message) {
    return new IllegalStateException(message);
  }
}
