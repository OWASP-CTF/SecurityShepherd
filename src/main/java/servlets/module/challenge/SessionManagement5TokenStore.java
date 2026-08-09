package servlets.module.challenge;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import utils.Hash;

/**
 * Used to help Session Management Challenge Five track real, server-issued password reset tokens.
 * SessionManagement5SetToken generates and stores a token here without ever returning it to the
 * client; SessionManagement5ChangePassword can then only succeed if the caller already possesses
 * the token that was actually issued.
 *
 * @author Mark Denihan
 */
public class SessionManagement5TokenStore {

  private static final long TOKEN_LIFETIME_MILLIS = 10 * 60 * 1000;
  private static final Map<String, TokenEntry> tokensByUserName = new ConcurrentHashMap<>();

  private static class TokenEntry {
    private final String token;
    private final long issuedAtMillis;

    private TokenEntry(String token, long issuedAtMillis) {
      this.token = token;
      this.issuedAtMillis = issuedAtMillis;
    }
  }

  /**
   * Generates and stores a new reset token for a user, replacing any previous one. The token itself
   * is not returned - it must reach the account holder out-of-band.
   *
   * @param userName The user to issue a token for
   */
  public static void issueToken(String userName) {
    tokensByUserName.put(userName, new TokenEntry(Hash.randomString(), System.currentTimeMillis()));
  }

  /**
   * Checks whether the submitted token matches the one actually issued to this user and is still
   * within its lifetime. On success, the token is consumed (removed) so it cannot be reused.
   *
   * @param userName The user the token should belong to
   * @param submittedToken The token value submitted by the caller
   * @return True if the token was valid and has now been consumed
   */
  public static boolean validateAndConsumeToken(String userName, String submittedToken) {
    TokenEntry entry = tokensByUserName.get(userName);
    if (entry == null || submittedToken == null || submittedToken.isEmpty()) {
      return false;
    }
    boolean valid =
        entry.token.equals(submittedToken)
            && (System.currentTimeMillis() - entry.issuedAtMillis) < TOKEN_LIFETIME_MILLIS;
    if (valid) {
      tokensByUserName.remove(userName);
    }
    return valid;
  }
}
