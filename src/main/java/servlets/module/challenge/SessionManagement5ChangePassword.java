package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Five - Change Password This is a level function - DOES NOT RETURN
 * KEY <br>
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
public class SessionManagement5ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5ChangePassword.class);
  private static String levelName = "Session Management Challenge Five (Change Password)";

  // private static String levelResult = ""; //This Servlet does not return a result

  /**
   * Function used by Session Management Challenge Five to change the password of an account. The
   * function requires the single use, time limited, account bound reset token that
   * SessionManagement5SetToken issued to this session. The account that is updated is read from
   * that server side record, never from the request.
   *
   * @param userName Sub schema user name the reset token was issued for
   * @param newPassword the password which to use to update an accounts password
   * @param resetPasswordToken The reset token issued out of band to the account owner
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement5", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      try {
        log.debug("Getting Challenge Parameters");
        Object passNewObj = request.getParameter("newPassword");
        Object userNewObj = request.getParameter("userName");
        Object tokenObj = request.getParameter("resetPasswordToken");
        String userName = new String();
        String newPass = new String();
        String token = new String();
        if (passNewObj != null) {
          newPass = (String) passNewObj;
        }
        if (userNewObj != null) {
          userName = (String) userNewObj;
        }
        if (tokenObj != null) {
          token = (String) tokenObj;
        }
        log.debug("userName = " + userName);
        // The new password and the reset token are secrets: they are never logged.

        // The reset token is only ever valid against the server side record created when the
        // reset mail was issued. It is random, single use, time limited and bound to one account.
        String storedTokenHash =
            (String) ses.getAttribute(SessionManagement5SetToken.RESET_TOKEN_HASH_ATTRIBUTE);
        String storedUserName =
            (String) ses.getAttribute(SessionManagement5SetToken.RESET_USER_ATTRIBUTE);
        Object storedExpiryObj =
            ses.getAttribute(SessionManagement5SetToken.RESET_EXPIRY_ATTRIBUTE);

        boolean tokenValid = false;
        if (storedTokenHash == null || storedUserName == null || storedExpiryObj == null) {
          log.debug("No password reset token has been issued for this session");
        } else if (System.currentTimeMillis() > ((Long) storedExpiryObj).longValue()) {
          log.debug("Password reset token has expired");
          clearResetState(ses);
        } else if (token.isEmpty()) {
          log.debug("No password reset token was submitted");
        } else if (!MessageDigest.isEqual(
            storedTokenHash.getBytes(StandardCharsets.UTF_8),
            SessionManagement5SetToken.sha256Hex(token).getBytes(StandardCharsets.UTF_8))) {
          log.debug("Submitted password reset token did not match the issued token");
          // Consume the token so that it cannot be guessed at over many requests
          clearResetState(ses);
        } else if (!storedUserName.equalsIgnoreCase(userName)) {
          log.debug("Password reset token was not issued for the submitted user name");
        } else {
          tokenValid = true;
        }

        if (!tokenValid) {
          htmlOutput = "<p>" + bundle.getString("changePass.oldToken") + "</p>";
        } else if (newPass.length() < 12) {
          log.debug("Invalid password submitted");
          htmlOutput = "<p>" + bundle.getString("changePass.failure") + "</p>";
        } else {
          // Single use: burn the token before it is acted upon
          clearResetState(ses);

          log.debug("Getting ApplicationRoot");
          String ApplicationRoot = getServletContext().getRealPath("");
          log.debug("Servlet root = " + ApplicationRoot);

          Connection conn =
              Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalFive");
          try {
            log.debug("Changing password for user: " + storedUserName);
            PreparedStatement callstmt;

            callstmt =
                conn.prepareStatement("UPDATE users SET userPassword = SHA(?) WHERE userName = ?");
            callstmt.setString(1, newPass);
            // The account is taken from the server side reset record, never from the request
            callstmt.setString(2, storedUserName);

            log.debug("Executing changePassword");
            callstmt.execute();

            log.debug("Committing changes made to database");
            callstmt = conn.prepareStatement("COMMIT");
            callstmt.execute();
            log.debug("Changes committed.");
          } finally {
            Database.closeConnection(conn);
          }

          htmlOutput = "<p>" + bundle.getString("changePass.success") + "</p>";
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - Change Password - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /**
   * Removes the server side password reset record so that a reset token can only ever be used once.
   *
   * @param ses The user's server side session
   */
  private static void clearResetState(HttpSession ses) {
    ses.removeAttribute(SessionManagement5SetToken.RESET_TOKEN_HASH_ATTRIBUTE);
    ses.removeAttribute(SessionManagement5SetToken.RESET_USER_ATTRIBUTE);
    ses.removeAttribute(SessionManagement5SetToken.RESET_EXPIRY_ATTRIBUTE);
  }
}
