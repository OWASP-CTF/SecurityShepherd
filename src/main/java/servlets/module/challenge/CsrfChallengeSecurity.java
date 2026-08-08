package servlets.module.challenge;

import javax.servlet.http.HttpSession;

/** Shared server-side identity rules for the CSRF challenge target endpoints. */
final class CsrfChallengeSecurity {

  private CsrfChallengeSecurity() {}

  static String authenticatedUserId(HttpSession session) {
    if (session == null) {
      return null;
    }
    Object userId = session.getAttribute("userStamp");
    if (!(userId instanceof String) || userId.toString().isEmpty()) {
      return null;
    }
    return userId.toString();
  }

  static String counterOwner(HttpSession session, String requestedUserId) {
    String authenticatedUserId = authenticatedUserId(session);
    if (authenticatedUserId == null
        || requestedUserId == null
        || authenticatedUserId.equals(requestedUserId)) {
      return null;
    }
    return authenticatedUserId;
  }
}
