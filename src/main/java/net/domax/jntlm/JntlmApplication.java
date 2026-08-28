/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm;

import net.domax.jntlm.config.JntlmProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * jntlm - a Java Spring Boot rewrite of the CNTLM NTLM-authenticating HTTP proxy.
 *
 * <p>The proxy accepts HTTP client connections (including CONNECT tunneling) and forwards them
 * through a parent proxy that requires NTLM authentication, transparently performing the NTLM
 * handshake on the client's behalf.
 */
@SpringBootApplication
@EnableConfigurationProperties(JntlmProperties.class)
public class JntlmApplication {

  public static void main(String[] args) {
    SpringApplication.run(JntlmApplication.class, args);
  }
}
