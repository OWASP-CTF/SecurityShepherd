package utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Server side state for the Session Management challenge account recovery flows. <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 */
public class SessionManagementRecoveryGuard {

  private static final Logger log = LogManager.getLogger(SessionManagementRecoveryGuard.class);
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /** Maximum number of secret answer submissions allowed per session, per challenge. */
  public static final int MAX_ATTEMPTS = 3;

  /**
   * How long a spent allowance takes to decay. Rate limiting is here to make a guessable secret
   * answer impractical to brute force, not to permanently disable recovery for someone who
   * mistyped, so the counter is windowed rather than absolute.
   */
  public static final long ATTEMPT_WINDOW_MILLIS = 15L * 60L * 1000L;

  private SessionManagementRecoveryGuard() {}

  private static String tokenAttribute(String challengeKey) {
    return "smRecoveryToken." + challengeKey;
  }

  private static String subjectAttribute(String challengeKey) {
    return "smRecoverySubject." + challengeKey;
  }

  private static String attemptAttribute(String challengeKey) {
    return "smRecoveryAttempts." + challengeKey;
  }

  private static String windowAttribute(String challengeKey) {
    return "smRecoveryWindowStart." + challengeKey;
  }

  /**
   * Returns the number of attempts already spent inside the current window, clearing the tally when
   * the window has elapsed.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   * @return Attempts spent in the live window
   */
  private static int attemptsInWindow(HttpSession ses, String challengeKey) {
    Object windowStart = ses.getAttribute(windowAttribute(challengeKey));
    if (windowStart instanceof Long
        && System.currentTimeMillis() - ((Long) windowStart).longValue() >= ATTEMPT_WINDOW_MILLIS) {
      resetAttempts(ses, challengeKey);
      return 0;
    }
    Object attempts = ses.getAttribute(attemptAttribute(challengeKey));
    return (attempts instanceof Integer) ? ((Integer) attempts).intValue() : 0;
  }

  /**
   * Clears the recovery attempt tally, so a successful recovery does not leave the flow half-locked
   * for the rest of the session.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   */
  public static void resetAttempts(HttpSession ses, String challengeKey) {
    ses.removeAttribute(attemptAttribute(challengeKey));
    ses.removeAttribute(windowAttribute(challengeKey));
  }

  /**
   * Issues a fresh 256 bit recovery token that is held server side in the caller's session and
   * bound to the account the recovery was requested for.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   * @param subject The account identifier the recovery was requested for
   * @return The token the client must present with its answer
   */
  public static String issueToken(HttpSession ses, String challengeKey, String subject) {
    byte[] raw = new byte[32];
    SECURE_RANDOM.nextBytes(raw);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    ses.setAttribute(tokenAttribute(challengeKey), token);
    ses.setAttribute(subjectAttribute(challengeKey), subject);
    return token;
  }

  /**
   * Constant time comparison of the submitted recovery token, and of the account it was issued for,
   * against the values held in the caller's session.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   * @param submittedToken The recovery token supplied by the client, may be null
   * @param subject The account identifier the client claims the token was issued for
   * @return True only if the token and the account both match the server side record
   */
  public static boolean isValidToken(
      HttpSession ses, String challengeKey, String submittedToken, String subject) {
    Object storedToken = ses.getAttribute(tokenAttribute(challengeKey));
    Object storedSubject = ses.getAttribute(subjectAttribute(challengeKey));
    if (storedToken == null || storedSubject == null || submittedToken == null || subject == null) {
      log.debug("No recovery token has been issued to this session");
      return false;
    }
    boolean tokenMatches =
        MessageDigest.isEqual(
            storedToken.toString().getBytes(StandardCharsets.UTF_8),
            submittedToken.getBytes(StandardCharsets.UTF_8));
    boolean subjectMatches =
        MessageDigest.isEqual(
            storedSubject.toString().getBytes(StandardCharsets.UTF_8),
            subject.getBytes(StandardCharsets.UTF_8));
    return tokenMatches && subjectMatches;
  }

  /**
   * Burns the recovery token so that it can only ever be redeemed once.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   */
  public static void consumeToken(HttpSession ses, String challengeKey) {
    ses.removeAttribute(tokenAttribute(challengeKey));
    ses.removeAttribute(subjectAttribute(challengeKey));
    // A completed recovery clears the tally: the allowance exists to slow guessing, and the
    // guessing is over.
    resetAttempts(ses, challengeKey);
  }

  /**
   * Returns true once this session has spent its allowance of recovery attempts.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   * @return True if no further recovery attempt may be made by this session
   */
  public static boolean isLockedOut(HttpSession ses, String challengeKey) {
    return attemptsInWindow(ses, challengeKey) >= MAX_ATTEMPTS;
  }

  /**
   * Records one recovery attempt against this session.
   *
   * @param ses The caller's server side session
   * @param challengeKey Namespace so that each challenge keeps its own state
   */
  public static void recordAttempt(HttpSession ses, String challengeKey) {
    int current = attemptsInWindow(ses, challengeKey);
    if (current == 0) {
      ses.setAttribute(windowAttribute(challengeKey), Long.valueOf(System.currentTimeMillis()));
    }
    ses.setAttribute(attemptAttribute(challengeKey), Integer.valueOf(current + 1));
  }
}
