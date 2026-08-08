package utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

public class ShepherdLogManager {

  private static final Logger log = LogManager.getLogger(ShepherdLogManager.class);
  private static final int MAX_LOG_VALUE_LENGTH = 256;

  public static void setRequestIp(String theIp) {
    ThreadContext.put("RemoteAddress", sanitizeLogValue(theIp));
  }

  public static void logEvent(String theIp, String theMessage) {
    setRequestIp(theIp);
    log.debug(sanitizeLogValue(theMessage));
  }

  public static void setRequestIp(String theIp, String theForwardedIp) {
    if (theForwardedIp != null
        && !theForwardedIp.isEmpty()) // If string is not null and not empty set normal message
    {
      ThreadContext.put(
          "RemoteAddress",
          sanitizeLogValue(theIp)
              + " (untrusted X-Forwarded-For: "
              + sanitizeLogValue(theForwardedIp)
              + ")");
    } else // No Forward Header detected so Log that
    {
      ThreadContext.put("RemoteAddress", sanitizeLogValue(theIp));
    }
  }

  public static void logEvent(String theIp, String theForwardedIp, String theMessage) {
    setRequestIp(theIp, theForwardedIp);
    log.debug(sanitizeLogValue(theMessage));
  }

  /**
   * Logs Event with username at beginning of log
   *
   * @param theIp
   * @param theForwardedIp
   * @param theMessage
   * @param theUser
   */
  public static void logEvent(
      String theIp, String theForwardedIp, String theMessage, Object theUser) {
    String userName = new String();
    if (theUser != null) {
      userName = sanitizeLogValue(theUser);
    }
    if (userName.isEmpty()) {
      userName = new String("UnknownUser");
    }
    setRequestIp(theIp, theForwardedIp, userName);
    log.debug(sanitizeLogValue(theMessage));
  }

  /**
   * Sets IP of request and preceeds it with the username of the logged in user
   *
   * @param theIp
   * @param theForwardedIp
   */
  public static void setRequestIp(String theIp, String theForwardedIp, String userName) {

    if (theForwardedIp != null
        && !theForwardedIp.isEmpty()) // If string is not null and not empty set normal message
    {
      ThreadContext.put(
          "RemoteAddress",
          sanitizeLogValue(userName)
              + " at "
              + sanitizeLogValue(theIp)
              + " (untrusted X-Forwarded-For: "
              + sanitizeLogValue(theForwardedIp)
              + ")");
    } else // No Forward Header detected so Log that
    {
      ThreadContext.put(
          "RemoteAddress", sanitizeLogValue(userName) + " at " + sanitizeLogValue(theIp));
    }
  }

  static String sanitizeLogValue(Object value) {
    if (value == null) {
      return "unknown";
    }
    String text = value.toString();
    StringBuilder sanitized = new StringBuilder(Math.min(text.length(), MAX_LOG_VALUE_LENGTH));
    for (int i = 0; i < text.length() && sanitized.length() < MAX_LOG_VALUE_LENGTH; i++) {
      char character = text.charAt(i);
      sanitized.append(Character.isISOControl(character) ? '_' : character);
    }
    return sanitized.toString();
  }
}
