package utils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Per session synchronizer tokens used to protect the state changing Cross Site Request Forgery
 * challenge targets. Tokens are minted server side with a SecureRandom, are held only in the user's
 * HttpSession, are bound to the user that owns that session and are compared in constant time. <br>
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
public final class CsrfSynchronizerTokens {

  private static final Logger log = LogManager.getLogger(CsrfSynchronizerTokens.class);
  private static final SecureRandom secureRandom = new SecureRandom();
  private static final String TOKEN_ATTRIBUTE_PREFIX = "csrfSynchronizerToken.";
  private static final String OWNER_ATTRIBUTE_SUFFIX = ".owner";
  private static final int TOKEN_BYTE_LENGTH = 32;

  private CsrfSynchronizerTokens() {}

  private static String tokenAttribute(String tokenName) {
    return TOKEN_ATTRIBUTE_PREFIX + tokenName;
  }

  private static String ownerAttribute(String tokenName) {
    return TOKEN_ATTRIBUTE_PREFIX + tokenName + OWNER_ATTRIBUTE_SUFFIX;
  }

  /**
   * Generates a new unguessable synchronizer token.
   *
   * @return A 256 bit URL safe random token
   */
  public static String newToken() {
    byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
    secureRandom.nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }

  /**
   * Stores a synchronizer token in the session and binds it to the user it was issued to.
   *
   * @param ses The session of the user the token was issued to
   * @param tokenName Unique name of the protected operation
   * @param ownerUserId The user identifier the token was issued to
   * @param token The token value to store
   */
  public static void setToken(HttpSession ses, String tokenName, String ownerUserId, String token) {
    if (ses == null
        || tokenName == null
        || tokenName.isEmpty()
        || ownerUserId == null
        || ownerUserId.isEmpty()
        || token == null
        || token.isEmpty()) {
      return;
    }
    synchronized (ses) {
      ses.setAttribute(tokenAttribute(tokenName), token);
      ses.setAttribute(ownerAttribute(tokenName), ownerUserId);
    }
  }

  /**
   * Returns the synchronizer token held in this session, but only when it was issued to the
   * submitted user. No token is minted by this method.
   *
   * @param ses The session of the user making the request
   * @param tokenName Unique name of the protected operation
   * @param ownerUserId The user identifier of the session holder
   * @return The token, or null when no token is bound to this session and user
   */
  public static String peekToken(HttpSession ses, String tokenName, String ownerUserId) {
    if (ses == null
        || tokenName == null
        || tokenName.isEmpty()
        || ownerUserId == null
        || ownerUserId.isEmpty()) {
      return null;
    }
    Object storedToken = ses.getAttribute(tokenAttribute(tokenName));
    Object storedOwner = ses.getAttribute(ownerAttribute(tokenName));
    if (storedToken == null || storedToken.toString().isEmpty()) {
      return null;
    }
    if (storedOwner == null || !ownerUserId.equals(storedOwner.toString())) {
      log.error("CSRF synchronizer token is not bound to the current session user");
      return null;
    }
    return storedToken.toString();
  }

  /**
   * Returns the synchronizer token bound to this session and user, minting and storing a new
   * cryptographically random one when the session does not hold one yet.
   *
   * @param ses The session of the user making the request
   * @param tokenName Unique name of the protected operation
   * @param ownerUserId The user identifier of the session holder
   * @return The session bound token, or an empty String when there is no authenticated user
   */
  public static String getOrCreateToken(HttpSession ses, String tokenName, String ownerUserId) {
    if (ses == null
        || tokenName == null
        || tokenName.isEmpty()
        || ownerUserId == null
        || ownerUserId.isEmpty()) {
      return "";
    }
    synchronized (ses) {
      String token = peekToken(ses, tokenName, ownerUserId);
      if (token == null) {
        token = newToken();
        setToken(ses, tokenName, ownerUserId, token);
        log.debug("Minted a new CSRF synchronizer token for " + tokenName);
      }
      return token;
    }
  }

  /**
   * Returns the synchronizer token bound to this session for the given token name, using the
   * authenticated user held in the session as the owner. A new token is minted when needed.
   *
   * @param ses The session of the currently authenticated user
   * @param tokenName Unique name of the protected operation
   * @return The session bound token, or an empty String when there is no authenticated user
   */
  public static String getToken(HttpSession ses, String tokenName) {
    if (ses == null) {
      return "";
    }
    Object sessionUser = ses.getAttribute("userStamp");
    if (sessionUser == null || sessionUser.toString().isEmpty()) {
      log.debug("No authenticated user in session, refusing to mint a CSRF token");
      return "";
    }
    return getOrCreateToken(ses, tokenName, sessionUser.toString());
  }

  /**
   * Constant time comparison of two token values.
   *
   * @param expected The token held server side
   * @param submitted The token submitted with the request
   * @return True only when both values are present and identical
   */
  public static boolean matches(String expected, String submitted) {
    if (expected == null || expected.isEmpty() || submitted == null || submitted.isEmpty()) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Compares the submitted token with the token bound to this session and user in constant time.
   *
   * @param ses The session of the user making the request
   * @param tokenName Unique name of the protected operation
   * @param ownerUserId The user identifier of the session holder
   * @param submittedToken The token value that came in with the request
   * @return True only when the request carried this session user's own valid token
   */
  public static boolean isValidToken(
      HttpSession ses, String tokenName, String ownerUserId, String submittedToken) {
    if (submittedToken == null || submittedToken.isEmpty()) {
      log.error("No CSRF synchronizer token was submitted with the request");
      return false;
    }
    String expected = peekToken(ses, tokenName, ownerUserId);
    if (expected == null) {
      log.error("No CSRF synchronizer token is bound to this session for " + tokenName);
      return false;
    }
    boolean result = matches(expected, submittedToken);
    if (!result) {
      log.error("Submitted CSRF synchronizer token did not match the session token");
    }
    return result;
  }

  /**
   * Compares the submitted token with the token bound to this session, using the authenticated user
   * held in the session as the owner.
   *
   * @param ses The session of the currently authenticated user
   * @param tokenName Unique name of the protected operation
   * @param submittedToken The token value that came in with the request
   * @return True only when the request carried this session user's own valid token
   */
  public static boolean isValidToken(HttpSession ses, String tokenName, String submittedToken) {
    if (ses == null) {
      return false;
    }
    Object sessionUser = ses.getAttribute("userStamp");
    if (sessionUser == null || sessionUser.toString().isEmpty()) {
      log.error("No authenticated user in session to validate a CSRF token against");
      return false;
    }
    return isValidToken(ses, tokenName, sessionUser.toString(), submittedToken);
  }

  /**
   * Reads the synchronizer token from the request, accepting both the dedicated csrfSyncToken
   * parameter and the csrfToken parameter name that some challenge pages already document.
   *
   * @param request The request to read the token from
   * @return The trimmed token value, or an empty String when no token was submitted
   */
  public static String getSubmittedToken(HttpServletRequest request) {
    if (request == null) {
      return "";
    }
    String submittedToken = request.getParameter("csrfSyncToken");
    if (submittedToken == null || submittedToken.trim().isEmpty()) {
      submittedToken = request.getParameter("csrfToken");
    }
    return submittedToken == null ? "" : submittedToken.trim();
  }

  /**
   * Defence in depth. When the browser supplies an Origin or Referer header it must name the host
   * that served this request. Requests carrying neither header are left to the synchronizer token,
   * which is the primary control.
   *
   * @param request The request to inspect
   * @return True when the request did not come from another origin
   */
  public static boolean isSameOrigin(HttpServletRequest request) {
    if (request == null) {
      return false;
    }
    String origin = request.getHeader("Origin");
    if (origin != null && !origin.isEmpty()) {
      return hostMatches(origin, request.getServerName());
    }
    String referer = request.getHeader("Referer");
    if (referer != null && !referer.isEmpty()) {
      return hostMatches(referer, request.getServerName());
    }
    return true;
  }

  private static boolean hostMatches(String candidateUrl, String expectedHost) {
    if (expectedHost == null || expectedHost.isEmpty()) {
      return false;
    }
    try {
      String host = new URI(candidateUrl).getHost();
      if (host == null) {
        log.error("Request origin has no host and is treated as cross origin");
        return false;
      }
      return host.equalsIgnoreCase(expectedHost);
    } catch (URISyntaxException e) {
      log.error("Could not parse request origin: " + e.toString());
      return false;
    }
  }
}
