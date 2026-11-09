/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import net.domax.jntlm.config.JntlmProperties;
import net.domax.jntlm.http.HttpIo;
import net.domax.jntlm.http.HttpMessage;
import net.domax.jntlm.ntlm.Credentials;
import net.domax.jntlm.ntlm.NtlmFlags;
import net.domax.jntlm.ntlm.NtlmMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Resolves the NTLM negotiate flags used in the Type-1 message towards the parent proxy.
 *
 * <p>Not part of CNTLM: CNTLM only offers the static per-dialect defaults plus a manual {@code
 * Flags} override (see {@code ntlm_request} in {@code ntlm.c}). Here, the parent proxy is probed
 * with a bounded list of candidate flags (see {@link NtlmFlags#candidates}); the first candidate
 * that completes the full handshake (Type-1 &rarr; Type-2 &rarr; Type-3 &rarr; non-407) is cached
 * for every later parent connection. If none works, the dialect default is used.
 *
 * <p>Only one detection runs at a time; concurrent callers wait for its result. The cache is
 * invalidated when the active parent changes, or via {@link #reportRejected(long)} when a fresh
 * handshake with the cached flags is rejected (subject to a cool-down).
 */
@Slf4j
@Component
public class NtlmFlagsResolver {

  static final int PROBE_TIMEOUT_MS = 10_000;
  static final int MAX_PROBES = 8;
  static final Duration COOLDOWN = Duration.ofSeconds(60);

  private static final int NTLM_CHALLENGE_MIN = 40;
  private static final String PROXY_AUTHORIZATION = "Proxy-Authorization";

  /** A resolved flags value, the parent it applies to and whether it was actually detected. */
  record Resolved(long flags, ParentProxy parent, boolean detected, Instant at) {}

  /** Outcome of probing one candidate; {@code serverFlags} is set when the Type-3 was rejected. */
  record ProbeOutcome(boolean accepted, String reason, long serverFlags) {

    static ProbeOutcome accept() {
      return new ProbeOutcome(true, null, 0);
    }

    static ProbeOutcome reject(String reason) {
      return new ProbeOutcome(false, reason, 0);
    }
  }

  private final ParentProxyManager parentProxyManager;
  private final Credentials globalCredentials;
  private final JntlmProperties properties;
  private final Clock clock;

  private final AtomicReference<CompletableFuture<Resolved>> current = new AtomicReference<>();

  @Autowired
  public NtlmFlagsResolver(
      ParentProxyManager parentProxyManager,
      Credentials globalCredentials,
      JntlmProperties properties) {
    this(parentProxyManager, globalCredentials, properties, Clock.systemUTC());
  }

  NtlmFlagsResolver(
      ParentProxyManager parentProxyManager,
      Credentials globalCredentials,
      JntlmProperties properties,
      Clock clock) {
    this.parentProxyManager = parentProxyManager;
    this.globalCredentials = globalCredentials;
    this.properties = properties;
    this.clock = clock;
  }

  /**
   * Returns the negotiate flags to use for a new parent connection, running (or waiting for)
   * detection when nothing is cached for the active parent. {@code request} is the client request
   * used to build a lazy probe; when {@code null}, the static flags are returned.
   */
  public long flagsFor(HttpMessage request) {
    if (!properties.getDetect().isEnabled() || request == null) return staticFlags();
    return resolve(() -> lazyTemplate(request)).flags();
  }

  /**
   * Reports that a fresh handshake using {@code flags} was rejected with 407. Clears the cache (so
   * the next request re-detects) if {@code flags} are the cached ones and the last detection is
   * older than {@link #COOLDOWN}.
   */
  public void reportRejected(long flags) {
    val f = current.get();
    if (f == null || !f.isDone()) return;

    val r = f.join();
    if (r.flags() != flags) return;

    if (Duration.between(r.at(), clock.instant()).compareTo(COOLDOWN) < 0) {
      log.debug("NTLM flags {} rejected within cool-down; keeping cache", NtlmFlags.hex(flags));
      return;
    }
    if (current.compareAndSet(f, null))
      log.info("NTLM flags {} rejected by parent; will re-detect", NtlmFlags.hex(flags));
  }

  /** Starts eager detection against {@code jntlm.detect.probe-url} once the app is ready. */
  @EventListener(ApplicationReadyEvent.class)
  public void onApplicationReady() {
    startEagerDetection();
  }

  /** Starts eager detection on a virtual thread; returns it, or {@code null} if not applicable. */
  Thread startEagerDetection() {
    val detect = properties.getDetect();
    if (!detect.isEnabled() || detect.getProbeUrl() == null) return null;

    final HttpMessage template;
    try {
      template = eagerTemplate(detect.getProbeUrl());
    } catch (IllegalArgumentException e) {
      log.warn("Ignoring jntlm.detect.probe-url: {}", e.getMessage());
      return null;
    }
    return Thread.ofVirtual().name("jntlm-flags-detect").start(() -> resolve(() -> template));
  }

  /** The explicit {@code jntlm.flags} if non-zero, otherwise the dialect default. */
  private long staticFlags() {
    val explicit = globalCredentials.getFlags();
    return explicit == 0 ? NtlmFlags.defaultFor(globalCredentials) : explicit;
  }

  /** Single-flight lookup: returns the cached result for the active parent or detects anew. */
  Resolved resolve(Supplier<HttpMessage> template) {
    while (true) {
      val existing = current.get();
      if (existing != null) {
        val r = existing.join();
        if (r.parent().equals(parentProxyManager.activeParent())) return r;
      }
      val mine = new CompletableFuture<Resolved>();
      if (current.compareAndSet(existing, mine)) return runDetection(mine, template);
    }
  }

  private Resolved runDetection(
      CompletableFuture<Resolved> future, Supplier<HttpMessage> template) {
    Resolved r;
    try {
      r = detect(template.get());
    } catch (RuntimeException e) {
      log.warn("NTLM flags detection failed: {}", e.toString());
      r = fallback();
    }
    future.complete(r);
    return r;
  }

  /** Probes candidates in order until one is accepted, otherwise falls back to the default. */
  Resolved detect(HttpMessage template) {
    val queue =
        new ArrayDeque<>(NtlmFlags.candidates(globalCredentials, globalCredentials.getFlags()));
    val tried = new HashSet<Long>();
    var probes = 0;
    while (!queue.isEmpty() && probes < MAX_PROBES) {
      long candidate = queue.poll();
      if (!tried.add(candidate)) continue;
      ++probes;

      val outcome = probe(candidate, template);
      if (outcome.accepted()) {
        val parent = parentProxyManager.activeParent();
        log.info(
            "Detected NTLM flags {} for parent {}; set jntlm.flags to pin them",
            NtlmFlags.hex(candidate),
            parent);
        return new Resolved(candidate, parent, true, clock.instant());
      }
      log.debug(
          "NTLM flags {} rejected by parent {}: {}",
          NtlmFlags.hex(candidate),
          parentProxyManager.activeParent(),
          outcome.reason());

      if (outcome.serverFlags() != 0) {
        val refined = NtlmFlags.refine(candidate, outcome.serverFlags(), globalCredentials);
        if (refined != 0 && !tried.contains(refined)) {
          queue.remove(refined);
          queue.addFirst(refined);
        }
      }
    }
    return fallback();
  }

  private Resolved fallback() {
    val parent = parentProxyManager.activeParent();
    val flags = NtlmFlags.defaultFor(globalCredentials);
    log.warn(
        "Could not detect working NTLM flags for parent {}; falling back to {}",
        parent,
        NtlmFlags.hex(flags));
    return new Resolved(flags, parent, false, clock.instant());
  }

  /**
   * Runs one full handshake with {@code candidate} on a fresh parent connection. The probe
   * connection is always closed (never pooled).
   */
  ProbeOutcome probe(long candidate, HttpMessage template) {
    val creds = globalCredentials.copy().setFlags(candidate);
    final Endpoint server;
    try {
      server = new Endpoint(parentProxyManager.connect());
    } catch (IOException e) {
      return ProbeOutcome.reject("connect failed: " + e.getMessage());
    }

    try (server) {
      server.socket().setSoTimeout(PROBE_TIMEOUT_MS);

      HttpIo.sendHeaders(server.out(), withAuth(template, NtlmMessages.type1Request(creds)));
      val reply1 = HttpIo.recvHeaders(server.in());
      if (reply1 == null) return ProbeOutcome.reject("no reply to Type-1");
      if (reply1.getCode() != 407) return ProbeOutcome.accept();

      HttpIo.dropBody(server.in(), reply1);
      val header = reply1.getHeaders().getFirst("Proxy-Authenticate");
      val challenge = header == null ? new byte[0] : ProxyAuthenticator.decodeChallenge(header);
      if (challenge.length <= NTLM_CHALLENGE_MIN) return ProbeOutcome.reject("no challenge");
      if (server.isPeerClosed()) return ProbeOutcome.reject("connection closed");

      val type3 = NtlmMessages.type3Response(challenge, creds);
      HttpIo.sendHeaders(server.out(), withAuth(template, type3));
      val reply2 = HttpIo.recvHeaders(server.in());
      if (reply2 == null) return ProbeOutcome.reject("no reply to Type-3");
      if (reply2.getCode() == 407)
        return new ProbeOutcome(false, "Type-3 rejected", NtlmFlags.fromChallenge(challenge));
      return ProbeOutcome.accept();
    } catch (IOException | RuntimeException e) {
      return ProbeOutcome.reject(e.toString());
    }
  }

  private static HttpMessage withAuth(HttpMessage template, byte[] ntlmMessage) {
    val m = template.copy();
    val headers = m.getHeaders();
    headers.modify(PROXY_AUTHORIZATION, "NTLM " + Base64.getEncoder().encodeToString(ntlmMessage));
    headers.modify("Proxy-Connection", "keep-alive");
    headers.modify("Content-Length", "0");
    headers.remove("Transfer-Encoding");
    return m;
  }

  /**
   * Builds a body-less probe from a client request: CONNECT is kept as is; any other method becomes
   * GET without body headers.
   */
  static HttpMessage lazyTemplate(HttpMessage request) {
    val t = request.copy();
    val headers = t.getHeaders();
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove("Connection");
    if (!t.isConnect()) {
      t.setMethod("GET");
      headers.remove("Content-Length");
      headers.remove("Transfer-Encoding");
      headers.remove("Content-Type");
      headers.remove("Expect");
    }
    return t;
  }

  /**
   * Builds a probe from {@code jntlm.detect.probe-url}: {@code http} &rarr; {@code GET <url>},
   * {@code https} &rarr; {@code CONNECT host:port} (port defaults to 443).
   *
   * @throws IllegalArgumentException if the URL is malformed or not http/https
   */
  static HttpMessage eagerTemplate(URI uri) {
    val scheme =
        Optional.ofNullable(uri.getScheme()).map(s -> s.toLowerCase(Locale.ROOT)).orElse("");
    val host = uri.getHost();
    if (host == null || host.isEmpty()) throw new IllegalArgumentException("no host in " + uri);

    final HttpMessage m;
    final int port;
    switch (scheme) {
      case "https" -> {
        port = uri.getPort() == -1 ? 443 : uri.getPort();
        val authority = host + ":" + port;
        m = HttpMessage.newRequest("CONNECT", authority, "HTTP/1.1");
        m.getHeaders().add("Host", authority);
      }
      case "http" -> {
        port = uri.getPort() == -1 ? 80 : uri.getPort();
        m = HttpMessage.newRequest("GET", uri.toString(), "HTTP/1.1");
        m.getHeaders().add("Host", uri.getPort() == -1 ? host : host + ":" + port);
      }
      default -> throw new IllegalArgumentException("unsupported scheme in " + uri);
    }
    m.setHost(host);
    m.setPort(port);
    return m;
  }
}
