package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Two <br>
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
public class SessionManagement2 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2.class);
  private static String levelName = "Session Management Challenge Two";

  /**
   * The user attempts to use this function to sign into a sub schema. If they successfully sign in
   * then they are able to retrieve the result key for the challenge If they sign in with a correct
   * user name but incorrect password then the email address of the user will be returned in a error
   * message
   *
   * @param subName Sub schema user name
   * @param subName Sub schema user password
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
        log.debug("Getting Challenge Parameters");
        Object nameObj = request.getParameter("subName");
        Object passObj = request.getParameter("subPassword");
        String subName = new String();
        String subPass = new String();
        if (nameObj != null) {
          subName = (String) nameObj;
        }
        if (passObj != null) {
          subPass = (String) passObj;
        }
        log.debug("subName = " + subName);
        log.debug("subPass = " + subPass);

        log.debug("Getting ApplicationRoot");
        String ApplicationRoot = getServletContext().getRealPath("");
        log.debug("Servlet root = " + ApplicationRoot);

        Connection conn =
            Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalTwo");
        log.debug("Checking credentials");
        PreparedStatement callstmt;

        log.debug("Committing changes made to database");
        callstmt = conn.prepareStatement("COMMIT");
        callstmt.execute();
        log.debug("Changes committed.");

        callstmt =
            conn.prepareStatement(
                "SELECT userName, userAddress FROM users WHERE userName = ? AND userPassword ="
                    + " SHA(?)");
        callstmt.setString(1, subName);
        callstmt.setString(2, subPass);
        log.debug("Executing authUser");
        ResultSet resultSet = callstmt.executeQuery();
        if (resultSet.next()) {
          log.debug("Successful Login");
          // The result key is no longer derived or emitted here. A correct-credential branch that
          // hands out the level key belongs to the pre-fix design; the account it checks for can
          // only be reached by defeating the authentication this level is about, so the branch is
          // now an ordinary welcome with nothing secret in it.
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.welcome")
                  + " "
                  + Encode.forHtml(resultSet.getString(1))
                  + "</h2>";
        } else {
          // A failed sign-in used to say which half was wrong, and for a name that existed it
          // handed back that account's email address to whoever guessed the name. That address is
          // precisely what the reset flow needs, so an unauthenticated caller could read a target's
          // address straight off the login form. The reply is now the same for a wrong name and a
          // wrong password, and discloses nothing about the account either way.
          log.debug("Login failed");
          htmlOutput = makeTable(bundle.getString("response.badLogin") + "<br/>", bundle);
        }
        Database.closeConnection(conn);
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  private static String makeTable(String userAddress, ResourceBundle bundle) {
    return "<table>"
        + userAddress
        + "<tr><td>"
        + bundle.getString("form.userName")
        + "</td><td><input type='text' id='subName'/></td></tr>"
        + "<tr><td>"
        + bundle.getString("form.password")
        + "</td><td><input type='password' id='subPassword'/></td></tr>"
        + "<tr><td colspan='2'><div id='submitButton'><input type='submit' value='"
        + bundle.getString("form.signIn")
        + "'/>"
        + "</div></td></tr>"
        + "</table>";
  }
}
