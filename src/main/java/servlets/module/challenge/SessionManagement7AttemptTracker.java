package servlets.module.challenge;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Used by Session Management Challenge 7 to rate-limit guesses at a target's secret answer. The
 * valid-answer space is a hardcoded 7-item whitelist, so without a limit an attacker can brute
 * force any target's answer in at most 7 requests.
 *
 * @author Mark Denihan
 */
public class SessionManagement7AttemptTracker {

  private static final int MAX_ATTEMPTS = 3;
  private static final long LOCKOUT_WINDOW_MILLIS = 5 * 60 * 1000;
  private static final Map<String, AttemptWindow> attemptsByEmail = new ConcurrentHashMap<>();

  private static class AttemptWindow {
    private final AtomicInteger count = new AtomicInteger(0);
    private volatile long windowStartMillis = System.currentTimeMillis();
  }

  /**
   * Checks whether a target email is currently locked out from further secret-answer attempts.
   *
   * @param subEmail The target's email address
   * @return True if the attempt limit has been reached within the current lockout window
   */
  public static boolean isLockedOut(String subEmail) {
    AttemptWindow window = attemptsByEmail.get(subEmail);
    if (window == null) {
      return false;
    }
    if (System.currentTimeMillis() - window.windowStartMillis > LOCKOUT_WINDOW_MILLIS) {
      attemptsByEmail.remove(subEmail);
      return false;
    }
    return window.count.get() >= MAX_ATTEMPTS;
  }

  /**
   * Records a failed secret-answer attempt against a target email, starting a new lockout window if
   * none is currently active.
   *
   * @param subEmail The target's email address
   */
  public static void recordFailedAttempt(String subEmail) {
    AttemptWindow window = attemptsByEmail.computeIfAbsent(subEmail, key -> new AttemptWindow());
    if (System.currentTimeMillis() - window.windowStartMillis > LOCKOUT_WINDOW_MILLIS) {
      window.windowStartMillis = System.currentTimeMillis();
      window.count.set(0);
    }
    window.count.incrementAndGet();
  }

  /**
   * Clears any recorded attempts for a target email, e.g. after a correct answer is submitted.
   *
   * @param subEmail The target's email address
   */
  public static void clearAttempts(String subEmail) {
    attemptsByEmail.remove(subEmail);
  }
}
