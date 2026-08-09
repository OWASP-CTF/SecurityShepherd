package utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Per session synchroniser token for state changing challenge requests <br>
 * <br>
 * The nonce is only ever rendered into the application's own pages, so a request that carries it
 * must have been issued from one of those pages rather than from an off site attacker. <br>
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
public class CsrfNonce {

  private static final Logger log = LogManager.getLogger(CsrfNonce.class);
  private static final String sessionAttribute = "csrfChallengeNonce";

  /**
   * Returns the session's synchroniser token, generating one on first use
   *
   * @param ses HttpSession of the user the token belongs to
   * @return The session's CSRF nonce
   */
  public static synchronized String getNonce(HttpSession ses) {
    Object nonce = ses.getAttribute(sessionAttribute);
    if (nonce == null || nonce.toString().isEmpty()) {
      nonce = Hash.randomString();
      ses.setAttribute(sessionAttribute, nonce);
    }
    return nonce.toString();
  }

  /**
   * Compares a submitted token with the token issued to this session
   *
   * @param ses HttpSession of the user making the request
   * @param submittedNonce Token submitted with the request
   * @return Boolean value stating whether or not the token belongs to this session
   */
  public static boolean isValid(HttpSession ses, String submittedNonce) {
    if (submittedNonce == null || submittedNonce.isEmpty()) {
      log.error("No CSRF nonce submitted");
      return false;
    }
    boolean result =
        MessageDigest.isEqual(
            getNonce(ses).getBytes(StandardCharsets.UTF_8),
            submittedNonce.getBytes(StandardCharsets.UTF_8));
    if (!result) {
      log.error("Submitted CSRF nonce does not belong to this session");
    }
    return result;
  }
}
