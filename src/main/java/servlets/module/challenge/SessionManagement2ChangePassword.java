package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
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
import org.owasp.encoder.Encode;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Two - Password Reset Servlet Does not return result key <br>
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
public class SessionManagement2ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2ChangePassword.class);
  private static String levelName = "Session Management Challenge Two (Change Pass)";
  public static String levelHash =
      "f5ddc0ed2d30e597ebacf5fdd117083674b19bb92ffc3499121b9e6a12c92959";

  /**
   * Resets the password of the sub-schema account identified by the submitted email address, and
   * returns the new password in the HTTP response.
   *
   * @param subEmail Sub schema user email address
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
            "i18n.servlets.challenges.sessionManagement.sessionManagement2", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      String htmlOutput = new String();
      log.debug(levelName + " Servlet accessed");
      try {
        log.debug("Getting Challenge Parameter");
        Object emailObj = request.getParameter("subEmail");
        String subEmail = new String();
        if (emailObj != null) {
          subEmail = (String) emailObj;
        }
        log.debug("subEmail = " + subEmail);

        log.debug("Getting ApplicationRoot");
        String ApplicationRoot = getServletContext().getRealPath("");

        String newPassword = Hash.randomString();
        String htmlResult = new String();
        try {
          Connection conn =
              Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalTwo");
          log.debug("Checking credentials");
          PreparedStatement callstmt =
              conn.prepareStatement("UPDATE users SET userPassword = SHA(?) WHERE userAddress = ?");
          callstmt.setString(1, newPassword);
          callstmt.setString(2, subEmail);
          log.debug("Executing resetPassword");
          callstmt.execute();
          log.debug("Statement executed");

          log.debug("Committing changes made to database");
          callstmt = conn.prepareStatement("COMMIT");
          callstmt.execute();
          log.debug("Changes committed.");

          htmlResult = Encode.forHtml(newPassword);
          Database.closeConnection(conn);
        } catch (SQLException e) {
          log.error(levelName + " SQL Error: " + e.toString());
        }
        log.debug("Outputting HTML");
        out.write(bundle.getString("response.changedTo") + " " + htmlResult);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
