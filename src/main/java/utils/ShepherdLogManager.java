package utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

public class ShepherdLogManager {

  private static final Logger log = LogManager.getLogger(ShepherdLogManager.class);

  /** Upper bound on a logged address, long enough for a chain of forwarded hops. */
  private static final int MAX_ADDRESS_LENGTH = 256;

  /**
   * Makes an address safe to interpolate into a log line.
   *
   * <p>The forwarded address is taken from the X-Forwarded-For request header, which is entirely
   * requester controlled, and log4j2 renders it into the prefix of every line through
   * %X{ctx:RemoteAddress}. Without stripping control characters a requester can terminate the
   * current record and append further ones, forging arbitrary log entries.
   *
   * @param value Untrusted value destined for the log prefix
   * @return The value with control characters removed and its length capped
   */
  private static String sanitiseForLog(String value) {
    if (value == null) {
      return null;
    }

    String sanitised = value.replaceAll("\\p{Cntrl}", "");
    if (sanitised.length() > MAX_ADDRESS_LENGTH) {
      sanitised = sanitised.substring(0, MAX_ADDRESS_LENGTH);
    }
    return sanitised;
  }

  public static void setRequestIp(String theIp) {
    ThreadContext.put("RemoteAddress", sanitiseForLog(theIp));
  }

  public static void logEvent(String theIp, String theMessage) {
    setRequestIp(theIp);
    log.debug(theMessage);
  }

  public static void setRequestIp(String theIp, String theForwardedIp) {
    String safeIp = sanitiseForLog(theIp);
    String safeForwardedIp = sanitiseForLog(theForwardedIp);

    if (safeForwardedIp != null
        && !safeForwardedIp.isEmpty()) // If string is not null and not empty set normal message
    {
      ThreadContext.put("RemoteAddress", safeIp + " from " + safeForwardedIp);
    } else // No Forward Header detected so Log that
    {
      ThreadContext.put("RemoteAddress", safeIp + " from ?.?.?.?");
    }
  }

  public static void logEvent(String theIp, String theForwardedIp, String theMessage) {
    setRequestIp(theIp, theForwardedIp);
    log.debug(theMessage);
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
      userName = theUser.toString();
    }
    if (userName.isEmpty()) {
      userName = new String("UnknownUser");
    }
    setRequestIp(theIp, theForwardedIp, userName);
    log.debug(theMessage);
  }

  /**
   * Sets IP of request and preceeds it with the username of the logged in user
   *
   * @param theIp
   * @param theForwardedIp
   */
  public static void setRequestIp(String theIp, String theForwardedIp, String userName) {

    String safeIp = sanitiseForLog(theIp);
    String safeForwardedIp = sanitiseForLog(theForwardedIp);
    String safeUserName = sanitiseForLog(userName);

    if (safeForwardedIp != null
        && !safeForwardedIp.isEmpty()) // If string is not null and not empty set normal message
    {
      ThreadContext.put(
          "RemoteAddress", safeUserName + " at " + safeIp + " from " + safeForwardedIp);
    } else // No Forward Header detected so Log that
    {
      ThreadContext.put("RemoteAddress", safeUserName + " at " + safeIp + " from ?.?.?.?");
    }
  }
}
