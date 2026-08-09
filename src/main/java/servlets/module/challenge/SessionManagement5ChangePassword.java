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
   * Function used by Session Management Challenge Five to change the password of the submitted user
   * name. The function requires the unpredictable, single-use reset token issued for this session
   * and user, within ten minutes of it being issued.
   *
   * @param userName User cookie used to store the user password to be reset
   * @param newPassword the password which to use to update an accounts password
   * @param resetPasswordToken Single-use reset token issued by SessionManagement5SetToken
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
      String errorMessage = new String();
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
        // The token used to be a base64 timestamp: anyone could mint one, and it named no
        // particular account, so it authorised resetting any user's password. It is now the
        // unpredictable value issued for this session, matched against the user it was issued
        // for and expired ten minutes after issue.
        String issuedToken = (String) ses.getAttribute(SessionManagement5.RESET_TOKEN);
        String issuedFor = (String) ses.getAttribute(SessionManagement5.RESET_TOKEN_USER);
        Long issuedAt = (Long) ses.getAttribute(SessionManagement5.RESET_TOKEN_ISSUED);

        boolean tokenAccepted =
            issuedToken != null
                && issuedFor != null
                && issuedAt != null
                && !token.isEmpty()
                && MessageDigest.isEqual(
                    issuedToken.getBytes(StandardCharsets.UTF_8),
                    token.getBytes(StandardCharsets.UTF_8))
                && issuedFor.equals(userName)
                && (System.currentTimeMillis() - issuedAt.longValue())
                    < SessionManagement5.RESET_TOKEN_TTL_MILLIS;

        if (!tokenAccepted) {
          log.debug("Reset token rejected");
          errorMessage += "<p>" + bundle.getString("changePass.badToken") + "</p>";
          out.write(errorMessage);
        } else {
          // Single use: burn the token before acting on it.
          ses.removeAttribute(SessionManagement5.RESET_TOKEN);
          ses.removeAttribute(SessionManagement5.RESET_TOKEN_USER);
          ses.removeAttribute(SessionManagement5.RESET_TOKEN_ISSUED);
          if (newPass.length() >= 12) {
            log.debug("Getting ApplicationRoot");
            String ApplicationRoot = getServletContext().getRealPath("");
            log.debug("Servlet root = " + ApplicationRoot);

            Connection conn =
                Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalFive");
            log.debug("Changing password for user: " + userName);
            PreparedStatement callstmt;

            callstmt =
                conn.prepareStatement("UPDATE users SET userPassword = SHA(?) WHERE userName = ?");

            callstmt.setString(1, newPass);
            callstmt.setString(2, userName);

            log.debug("Executing changePassword");
            callstmt.execute();

            log.debug("Committing changes made to database");
            callstmt = conn.prepareStatement("COMMIT");
            callstmt.execute();
            log.debug("Changes committed.");

            htmlOutput = "<p>" + bundle.getString("changePass.success") + "</p>";
          } else {
            log.debug("Invalid password submitted");
            htmlOutput = "<p>" + bundle.getString("changePass.failure") + "</p>";
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
}
