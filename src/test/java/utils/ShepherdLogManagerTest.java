package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The forwarded address comes from the X-Forwarded-For header, and log4j2 renders it into the
 * prefix of every log line through %X{ctx:RemoteAddress}. A value containing a line break would let
 * a requester terminate the current record and append further ones, forging arbitrary log entries.
 */
public class ShepherdLogManagerTest {

  private static final String REMOTE_ADDRESS = "RemoteAddress";

  @AfterEach
  public void clearContext() {
    ThreadContext.clearMap();
  }

  @Test
  public void setRequestIp_forwardedAddressWithNewline_stripsLineBreaks() {
    ShepherdLogManager.setRequestIp("10.0.0.5", "1.2.3.4\nFATAL forged entry");

    String logged = ThreadContext.get(REMOTE_ADDRESS);
    assertFalse(logged.contains("\n"), "newline must not survive into the log prefix");
    assertFalse(logged.contains("\r"), "carriage return must not survive into the log prefix");
  }

  @Test
  public void setRequestIp_forwardedAddressWithCarriageReturn_stripsLineBreaks() {
    ShepherdLogManager.setRequestIp("10.0.0.5", "1.2.3.4\r\nWARN forged");

    assertFalse(ThreadContext.get(REMOTE_ADDRESS).contains("\r"));
    assertFalse(ThreadContext.get(REMOTE_ADDRESS).contains("\n"));
  }

  @Test
  public void setRequestIp_withUserName_stripsLineBreaks() {
    ShepherdLogManager.setRequestIp("10.0.0.5", "1.2.3.4\nforged", "alice\nforged");

    assertFalse(ThreadContext.get(REMOTE_ADDRESS).contains("\n"));
  }

  @Test
  public void setRequestIp_singleArgument_stripsLineBreaks() {
    ShepherdLogManager.setRequestIp("10.0.0.5\nforged");

    assertFalse(ThreadContext.get(REMOTE_ADDRESS).contains("\n"));
  }

  @Test
  public void setRequestIp_ordinaryAddresses_areUnchanged() {
    ShepherdLogManager.setRequestIp("10.0.0.5", "203.0.113.9");

    assertEquals("10.0.0.5 from 203.0.113.9", ThreadContext.get(REMOTE_ADDRESS));
  }

  @Test
  public void setRequestIp_noForwardedHeader_usesPlaceholder() {
    ShepherdLogManager.setRequestIp("10.0.0.5", null);

    assertEquals("10.0.0.5 from ?.?.?.?", ThreadContext.get(REMOTE_ADDRESS));
  }

  @Test
  public void setRequestIp_overlongForwardedHeader_isCapped() {
    StringBuilder longHeader = new StringBuilder();
    for (int i = 0; i < 500; i++) {
      longHeader.append("a");
    }

    ShepherdLogManager.setRequestIp("10.0.0.5", longHeader.toString());

    String logged = ThreadContext.get(REMOTE_ADDRESS);
    assertTrue(logged.length() < 500, "an oversized forwarded header must be truncated");
  }
}
