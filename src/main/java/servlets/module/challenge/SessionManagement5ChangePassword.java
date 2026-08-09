package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Date;
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
   * name. The function requires a valid token which is a base64'd timestamp. If the current time is
   * within 10 minutes of the token, the function will execute
   *
   * @param userName User cookie used to store the user password to be reset
   * @param newPassword the password which to use to update an accounts password
   * @param resetPasswordToken Base64'd time stamp
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
      int tokenLife = 11;
      Connection conn = null;
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
        // The token must be the unguessable value the server issued for this account. It used
        // to be base64 of the time the request was made, which anybody could recompute.
        Object issuedToken = ses.getAttribute("sessionManagement5Token");
        Object issuedFor = ses.getAttribute("sessionManagement5TokenUser");
        Object issuedAt = ses.getAttribute("sessionManagement5TokenIssued");
        boolean tokenMatches =
            issuedToken != null
                && issuedFor != null
                && issuedAt instanceof Long
                && !token.isEmpty()
                && issuedToken.equals(token)
                && issuedFor.equals(userName);
        if (!tokenMatches) {
          log.error("No reset token issued for the submitted account matched. Ending Servlet.");
          errorMessage += "<p>" + bundle.getString("changePass.badTokenData") + "</p>";
          out.write(errorMessage);
        } else {
          Date currentDateTime = new Date();
          tokenLife =
              (int) ((currentDateTime.getTime() / 60000) - (((Long) issuedAt).longValue() / 60000));
          log.debug("Token life = " + tokenLife);

          if (tokenLife < 10 && tokenLife >= 0) {
            if (newPass.length() >= 12) {
              log.debug("Getting ApplicationRoot");
              String ApplicationRoot = getServletContext().getRealPath("");
              log.debug("Servlet root = " + ApplicationRoot);

              conn =
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

              // Single use: the token cannot be replayed once it has changed a password.
              ses.removeAttribute("sessionManagement5Token");
              ses.removeAttribute("sessionManagement5TokenUser");
              ses.removeAttribute("sessionManagement5TokenIssued");
              htmlOutput = "<p>" + bundle.getString("changePass.success") + "</p>";
            } else {
              log.debug("Invalid password submitted: " + newPass);
              htmlOutput = "<p>" + bundle.getString("changePass.failure") + "</p>";
            }
          } else {
            if (!errorMessage.isEmpty()) {
              htmlOutput = "<p><font colour='red'><b>" + errorMessage + "</b></font</p>";
            } else if (tokenLife >= 10) {
              log.debug("Token too old");
              htmlOutput = "<p>" + bundle.getString("changePass.oldToken") + "</p>";
            } else if (tokenLife < 0) {
              log.debug("Token to young");
              htmlOutput = "<p>" + bundle.getString("changePass.youngToken") + "</p>";
            } else {
              log.error("Token to Strange: Unexpected Error");
              htmlOutput = "<p>" + bundle.getString("changePass.funkyToken") + "</p>";
            }
          }
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - Change Password - " + e.toString());
      } finally {
        // Nothing ever handed this connection back. Twenty requests emptied the challenge pool
        // and the module stopped answering anybody.
        Database.closeConnection(conn);
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
