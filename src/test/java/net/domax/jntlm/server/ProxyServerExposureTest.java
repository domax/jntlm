/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import java.util.concurrent.Executors;
import lombok.val;
import net.domax.jntlm.config.JntlmConfig;
import net.domax.jntlm.config.JntlmProperties;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;

/** Startup exposure warning ({@code specs/client-authentication}). */
class ProxyServerExposureTest {

  @ParameterizedTest(name = "{0} clientAuth={1} -> warn={2}")
  @CsvSource({"0.0.0.0, false, true", "127.0.0.1, false, false", "0.0.0.0, true, false"})
  void exposureWarning(String address, boolean clientAuth, boolean expectWarn) {
    val props = new JntlmProperties();
    props.setListenAddress(address);
    props.setListenPort(0);
    if (clientAuth) {
      props.getClientAuth().setEnabled(true);
      val user = new JntlmProperties.User();
      user.setUsername("alice");
      user.setPassword("secret");
      props.getClientAuth().setUsers(List.of(user));
    }

    val logger = (Logger) LoggerFactory.getLogger(ProxyServer.class);
    val appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    val server =
        new ProxyServer(
            props,
            null,
            Executors.newVirtualThreadPerTaskExecutor(),
            new JntlmConfig().clientAuthenticator(props));
    try {
      server.start();
      assertTrue(server.isRunning(), "listener must start normally");

      val warnings =
          appender.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .map(ILoggingEvent::getFormattedMessage)
              .filter(m -> m.contains("jntlm.client-auth.enabled"))
              .toList();
      assertEquals(expectWarn ? 1 : 0, warnings.size(), warnings.toString());
      if (expectWarn) {
        assertTrue(warnings.getFirst().contains(address), warnings.getFirst());
        assertTrue(warnings.getFirst().contains("127.0.0.1"), warnings.getFirst());
      }
    } finally {
      server.stop();
      logger.detachAppender(appender);
    }
  }
}
