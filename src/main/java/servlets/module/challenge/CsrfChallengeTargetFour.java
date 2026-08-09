package servlets.module.challenge;

import dbProcs.Database;
import dbProcs.Getter;
import dbProcs.Setter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.CsrfSynchronizerTokens;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Cross Site Request Forgery Challenge Target Four - Does not return Result key <br>
 * <br>
 * Weak Nonce Variety can be broken <br>
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
 *
 * @author Mark Denihan
 */
public class CsrfChallengeTargetFour extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static String moduleHash =
      "84118752e6cd78fecc3563ba2873d944aacb7b72f28693a23f9949ac310648b5";
  private static final Logger log = LogManager.getLogger(CsrfChallengeTargetFour.class);
  private static String levelName = "CSRF Target 4";

  /** Name of the per session synchronizer token that guards this state changing endpoint. */
  public static final String CSRF_TOKEN_NAME = "csrfChallengeFourNonce";

  /**
   * Increments the CSRF counter of the submitted user identifier. The submitted csrfToken must be
   * the nonce that was issued to the user making this request, so a nonce belonging to any other
   * user, or a request forged by another origin, is rejected.
   *
   * @param userId User identifier to be incremented
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug(levelName + " Servlet");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);

    String storedToken = new String();
    try {
      String ApplicationRoot = getServletContext().getRealPath("");
      boolean result = false;
      HttpSession ses = request.getSession(true);
      String userId = (String) ses.getAttribute("userStamp");
      if (Validate.validateSession(ses) && userId != null && !userId.isEmpty()) {
        ShepherdLogManager.setRequestIp(
            request.getRemoteAddr(),
            request.getHeader("X-Forwarded-For"),
            ses.getAttribute("userName").toString());
        log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
        // Get the synchronizer token of this session. It is bound to the user that owns the
        // session and it is never written into this response, so an off site attacker who can
        // only make this browser send requests is unable to learn it
        storedToken = CsrfSynchronizerTokens.peekToken(ses, CSRF_TOKEN_NAME, userId);
        if (storedToken == null || storedToken.isEmpty()) {
          log.debug("No CSRF Token found in session");
          storedToken =
              Setter.setCsrfChallengeFourCsrfToken(userId, Hash.randomString(), ApplicationRoot);
          CsrfSynchronizerTokens.setToken(ses, CSRF_TOKEN_NAME, userId, storedToken);
        }
        log.debug("Victom is - " + userId);
        String plusId = Validate.validateParameter(request.getParameter("userId"), 64).trim();
        log.debug("User Submitted - " + plusId);
        String csrfToken =
            Validate.validateParameter(request.getParameter("csrfToken"), 191).trim();

        if (!CsrfSynchronizerTokens.isSameOrigin(request)) {
          log.error(levelName + " request rejected. Cross origin request detected");
        } else if (!CsrfSynchronizerTokens.matches(storedToken, csrfToken)
            || !validCsrfToken(ApplicationRoot, userId, csrfToken)) {
          log.debug("User " + plusId + " CSRF attack failed due to invalid nonce");
        } else if (plusId.isEmpty() || userId.equals(plusId)) {
          log.debug("User " + userId + " is attacking themselves");
        } else {
          log.debug("Valid Nonce Value Submitted");
          String userName = (String) ses.getAttribute("userName");
          String attackerName = Getter.getUserName(ApplicationRoot, plusId);
          if (attackerName != null) {
            log.debug(userName + " is been CSRF'd by " + attackerName);

            log.debug("Attempting to Increment ");
            String moduleId = Getter.getModuleIdFromHash(ApplicationRoot, moduleHash);
            result = Setter.updateCsrfCounter(ApplicationRoot, moduleId, plusId);
          } else {
            log.error("UserId '" + plusId + "' could not be found in system.");
          }
        }

        if (result) {
          out.write(csrfGenerics.getString("target.incrementSuccess"));
        } else {
          out.write(csrfGenerics.getString("target.incrementFailed"));
        }
      } else {
        out.write(csrfGenerics.getString("target.noSession"));
      }
    } catch (Exception e) {
      out.write(errors.getString("error.funky"));
      log.fatal(levelName + " - " + e.toString());
    }
  }

  /**
   * CSRF Validator that confirms that the submitted CSRF token is the token that was issued to the
   * user making this request. The lookup is filtered by that user, so a token belonging to any
   * other user is rejected.
   *
   * @param ApplicationRoot Running context of the application
   * @param userId The identifier of the user making the request
   * @param csrfToken CSRF Token value submitted with the request
   * @return Returns true if the CSRF Token belongs to the requesting user
   */
  private static boolean validCsrfToken(String ApplicationRoot, String userId, String csrfToken) {
    log.debug("*** CSRF4.validCsrfToken ***");
    boolean result = false;

    if (userId == null || userId.isEmpty() || csrfToken == null || csrfToken.isEmpty()) {
      log.error("CSRF4 Token Check called without a user or a token");
      return false;
    }

    try (Connection conn = Database.getChallengeConnection(ApplicationRoot, "csrfChallengeFour");
        PreparedStatement prepstmt =
            conn.prepareStatement("SELECT csrfTokenscol FROM csrfTokens WHERE userId = ?")) {
      prepstmt.setString(1, userId);
      try (ResultSet rs = prepstmt.executeQuery()) {
        if (rs.next()) {
          result = CsrfSynchronizerTokens.matches(rs.getString(1), csrfToken);
        } else {
          log.debug("No CSRF token has been issued to this user");
        }
      }
    } catch (SQLException e) {
      log.error("CSRF4 Token Check Failure: " + e.toString());
      result = false;
    }
    log.debug("*** END CSRF4.validCsrfToken ***");
    return result;
  }
}
