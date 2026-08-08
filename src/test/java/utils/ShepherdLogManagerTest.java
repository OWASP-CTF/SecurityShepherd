package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ShepherdLogManagerTest {

  @AfterEach
  void clearContext() {
    ThreadContext.clearAll();
  }

  @Test
  void sanitizeLogValue_removesControlCharactersAndBoundsLength() {
    String sanitized = ShepherdLogManager.sanitizeLogValue("alice\r\nforged\tentry");

    assertEquals("alice__forged_entry", sanitized);
    assertEquals(256, ShepherdLogManager.sanitizeLogValue("a".repeat(300)).length());
  }

  @Test
  void forwardedHeader_isClearlyUntrustedAndCannotForgeALogLine() {
    ShepherdLogManager.setRequestIp("192.0.2.10", "203.0.113.5\r\nADMIN");

    String context = ThreadContext.get("RemoteAddress");
    assertTrue(context.startsWith("192.0.2.10"));
    assertTrue(context.contains("untrusted X-Forwarded-For"));
    assertFalse(context.contains("\r"));
    assertFalse(context.contains("\n"));
  }
}
