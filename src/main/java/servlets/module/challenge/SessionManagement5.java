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
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Five <br>
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
public class SessionManagement5 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5.class);

  // The sign in form offered an unlimited number of password guesses against a small, fixed
  // set of accounts, so the number of failures one session may accumulate is capped
  private static final String FAILED_SIGN_INS = "sessionManagement5FailedSignIns";

  private static final int MAX_FAILED_SIGN_INS = 10;
  private static String levelName = "Session Management Challenge Five";
  public static String levelHash =
      "7aed58f3a00087d56c844ed9474c671f8999680556c127a19ee79fa5d7a132e1";
  private static String levelResult = "a15b8ea0b8a3374a1dedc326dfbe3dbae26";

  /**
   * Users must use this functionality to sign in as an administrator to retrieve the result key.
   *
   * @param userName Sub schema user name
   * @param password Sub schema user password
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
      log.debug(levelName + " Servlet Accessed");
      Connection conn = null;
      try {
        log.debug("Getting Challenge Parameters");
        Object nameObj = request.getParameter("subUserName");
        Object passObj = request.getParameter("subUserPassword");
        String subName = new String();
        String subPass = new String();
        String userAddress = new String();
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

        conn = Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalFive");
        log.debug("Checking credentials");
        PreparedStatement callstmt;

        log.debug("Committing changes made to database");
        callstmt = conn.prepareStatement("COMMIT");
        callstmt.execute();
        log.debug("Changes committed.");

        // The role is never resolved before the credential is checked, so the sign in form cannot
        // be used to tell a real account from an absent one, or an administrator from a guest
        callstmt =
            conn.prepareStatement(
                "SELECT userName, userRole FROM users WHERE userName = ? AND userPassword ="
                    + " SHA(?)");
        callstmt.setString(1, subName);
        callstmt.setString(2, subPass);
        log.debug("Executing Login Check");
        Integer failedSignIns = (Integer) ses.getAttribute(FAILED_SIGN_INS);
        if (failedSignIns == null) {
          failedSignIns = 0;
        }
        ResultSet resultSet = callstmt.executeQuery();
        if (failedSignIns < MAX_FAILED_SIGN_INS
            && resultSet.next()
            && resultSet.getString(2).equalsIgnoreCase("admin")) {
          log.debug("Successful Admin Login");
          ses.removeAttribute(FAILED_SIGN_INS);
          // Get key and add it to the output
          String userKey =
              Hash.generateUserSolution(levelResult, (String) ses.getAttribute("userName"));

          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.welcome")
                  + " "
                  + Encode.forHtml(resultSet.getString(1))
                  + "</h2>"
                  + "<p>"
                  + bundle.getString("response.resultKey")
                  + " <a>"
                  + userKey
                  + "</a>"
                  + "</p>";
        } else {
          // One message for a bad user name, a bad password and a non admin account, so the sign
          // in form cannot be used to enumerate accounts or to locate the administrators
          log.debug("Incorrect credentials");
          ses.setAttribute(FAILED_SIGN_INS, failedSignIns + 1);
          userAddress = bundle.getString("response.badUser") + "<br/>";
          htmlOutput = makeTable(userAddress, bundle);
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      } finally {
        Database.closeConnection(conn);
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
        + "</td><td><input type='text' id='subUserName'/></td></tr>"
        + "<tr><td>"
        + bundle.getString("form.password")
        + "</td><td><input type='password' id='subUserPassword'/></td></tr>"
        + "<tr><td colspan='2'><div id='submitButton'><input type='submit' value='"
        + bundle.getString("form.signIn")
        + "'/>"
        + "</div></td></tr>"
        + "</table>";
  }

  private static String makeTable(ResourceBundle bundle) {
    return "<table><tr><td>"
        + bundle.getString("form.userName")
        + "</td><td><input type='text' id='subUserName'/></td></tr>"
        + "<tr><td>"
        + bundle.getString("form.password")
        + "</td><td><input type='password' id='subUserPassword'/></td></tr>"
        + "<tr><td colspan='2'><div id='submitButton'><input type='submit' value='"
        + bundle.getString("form.signIn")
        + "'/>"
        + "</div></td></tr>"
        + "</table>";
  }
}
