/* JNTLM © Licensed under MIT 2026. */
package net.domax.jntlm.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import net.domax.jntlm.config.JntlmProperties;
import org.junit.jupiter.api.Test;

/** Tests for {@link ParentProxyManager}. */
class ParentProxyManagerTest {

  @Test
  void activeParentIsFirstConfiguredInitially() {
    JntlmProperties props = new JntlmProperties();
    props.setParents(List.of("a.example.com:8080", "b.example.com:3128"));
    ParentProxyManager manager = new ParentProxyManager(props, new ConnectionPool());
    assertEquals(new ParentProxy("a.example.com", 8080), manager.activeParent());
  }
}
