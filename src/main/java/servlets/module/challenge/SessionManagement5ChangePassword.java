package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
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
   * Function used by Session Management Challenge Five to change the password of the submitted user
   * name. The function requires the exact, unguessable token that was issued to that same user name
   * by {@link SessionManagement5SetToken}. If the token matches and is still within 10 minutes of
   * being issued, the function will execute and the token is consumed (single use).
   *
   * @param userName User cookie used to store the user password to be reset
   * @param newPassword the password which to use to update an accounts password
   * @param resetPasswordToken The token previously issued for this exact user name
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
        log.debug("newPass = " + newPass);
        log.debug("token = " + token);

        // The token is only ever valid if it is the exact, unguessable value this application
        // itself generated and handed out for THIS user name via SessionManagement5SetToken.
        // Unlike a self-describing timestamp, nothing here can be derived or forged purely from
        // the current time - the reset request has to have genuinely happened first.
        SessionManagement5SetToken.TokenRecord issuedToken =
            SessionManagement5SetToken.RESET_TOKENS.get(userName);

        if (issuedToken == null || token.isEmpty() || !tokensMatch(token, issuedToken.token)) {
          log.debug("No matching outstanding reset token for user: " + userName);
          htmlOutput = "<p>" + bundle.getString("changePass.funkyToken") + "</p>";
        } else {
          long tokenLife = (System.currentTimeMillis() - issuedToken.issuedAtMillis) / 60000;
          log.debug("Token life (minutes) = " + tokenLife);

          if (tokenLife < 10 && tokenLife >= 0) {
            if (newPass.length() >= 12) {
              log.debug("Getting ApplicationRoot");
              String ApplicationRoot = getServletContext().getRealPath("");
              log.debug("Servlet root = " + ApplicationRoot);

              Connection conn =
                  Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalFive");
              log.debug("Changing password for user: " + userName);
              log.debug("Changing password to: " + newPass);
              PreparedStatement callstmt;

              callstmt =
                  conn.prepareStatement(
                      "UPDATE users SET userPassword = SHA(?) WHERE userName = ?");

              callstmt.setString(1, newPass);
              callstmt.setString(2, userName);

              log.debug("Executing changePassword");
              callstmt.execute();

              log.debug("Committing changes made to database");
              callstmt = conn.prepareStatement("COMMIT");
              callstmt.execute();
              log.debug("Changes committed.");

              // Single use - the token must not be replayable once it has been redeemed.
              SessionManagement5SetToken.RESET_TOKENS.remove(userName);

              htmlOutput = "<p>" + bundle.getString("changePass.success") + "</p>";
            } else {
              log.debug("Invalid password submitted: " + newPass);
              htmlOutput = "<p>" + bundle.getString("changePass.failure") + "</p>";
            }
          } else if (tokenLife >= 10) {
            log.debug("Token too old");
            SessionManagement5SetToken.RESET_TOKENS.remove(userName);
            htmlOutput = "<p>" + bundle.getString("changePass.oldToken") + "</p>";
          } else {
            log.error("Token life negative: Unexpected Error");
            htmlOutput = "<p>" + bundle.getString("changePass.funkyToken") + "</p>";
          }
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

  /** Constant-time comparison so token validation timing cannot leak information about it. */
  private static boolean tokensMatch(String submitted, String issued) {
    return MessageDigest.isEqual(
        submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        issued.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}
