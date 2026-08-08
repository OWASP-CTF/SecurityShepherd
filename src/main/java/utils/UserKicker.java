package utils;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Used to help application kick users that have been suspended
 *
 * @author Mark Denihan
 */
public class UserKicker {

  private static final Logger log = LogManager.getLogger(UserKicker.class);
  private static final Set<String> kickTheseUsers = ConcurrentHashMap.newKeySet();

  /**
   * Add's a specific user to the kick list
   *
   * @param userName The user name to kick
   */
  public static void addUserToKickList(String userName) {
    if (userName != null && !userName.isEmpty()) {
      log.debug("Adding a user to the kick list");
      kickTheseUsers.add(userName);
    }
  }

  /**
   * Tells you if a user is on the kick list
   *
   * @param userName User to search the list for
   * @return True if the user should be kicked
   */
  public static boolean shouldKickUser(String userName) {
    if (userName != null && !kickTheseUsers.isEmpty()) {
      log.debug("Kick list Is Not Empty! Checking...");
      boolean kickUser = kickTheseUsers.contains(userName);
      if (kickUser) {
        log.debug("A user is in the kick list");
      }
      return kickUser;
    } else {
      // log.debug("Empty Kick List! Skiping...");
      return false;
    }
  }

  /**
   * Removes a user from the kick list. Should be used after user has been kicked
   *
   * @param userName Username of the user to remove from kick list
   */
  public static void removeFromKicklist(String userName) {
    if (userName != null && kickTheseUsers.remove(userName)) {
      log.debug("Removing a user from the kick list");
    }
  }
}
