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
 * Level : SQL Injection 7 <br>
 * <br>
 *
 * <p>This file is part of the Security Shepherd Project.
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
public class SqlInjection7 extends HttpServlet {

  private static final String levelName = "SQLi C7";
  private static String levelHash =
      "8c2dd7e9818e5c6a9f8562feefa002dc0e455f0e92c8a46ab0cf519b1547eced";
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SqlInjection7.class);

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle bundle = ResourceBundle.getBundle("i18n.servlets.challenges.sqli.sqli7", locale);
    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      String applicationRoot = getServletContext().getRealPath("");

      try {
        String subEmail = Validate.validateParameter(request.getParameter("subEmail"), 60);
        log.debug("subEmail - " + subEmail.replaceAll("\n", " \\\\n ")); // Escape \n's
        String subPassword = Validate.validateParameter(request.getParameter("subPassword"), 40);
        log.debug("subPassword - " + subPassword);
        // Checked as it is used, and against a plain address charset.
        //
        // The check used to run over a copy with the newlines taken out while the lookup went on
        // to use the original, so the value that was approved and the value that was used were
        // not the same string. RFC 5321 also allows a quoted local part, which the general
        // validator accepts, and that form may carry quotes, spaces and control characters -- so
        // an address could pass validation and still arrive carrying SQL metacharacters.
        //
        // Restricting the address to the unquoted form means what was approved is what is used.
        boolean validEmail =
            subEmail.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\\.[A-Za-z0-9-]{1,63})*\\.[A-Za-z]{2,63}");
        if (!subPassword.isEmpty() && !subPassword.isEmpty() && validEmail) {
          Connection conn = Database.getChallengeConnection(applicationRoot, "SqlChallengeSeven");
          try {
            log.debug("Signing in with subitted details");
            PreparedStatement prepstmt =
                conn.prepareStatement(
                    "SELECT userName FROM users WHERE userEmail = ? AND userPassword = ?;");
            prepstmt.setString(1, subEmail);
            prepstmt.setString(2, subPassword);
            ResultSet users = prepstmt.executeQuery();
            if (users.next()) {
              // Signing in no longer prints the module result key. The stored credentials are
              // plain text and compared as plain text, so anyone holding a valid pair could read
              // the key straight out of a legitimate login without going near the injection this
              // challenge is about.
              htmlOutput =
                  "<h3>"
                      + bundle.getString("response.welcome")
                      + " "
                      + Encode.forHtml(users.getString(1))
                      + "</h3>";
            } else {
              htmlOutput =
                  "<h3>"
                      + bundle.getString("response.incorrectCreds")
                      + "</h3><p>"
                      + bundle.getString("response.carefulNow")
                      + "</p>";
            }
          } catch (Exception e) {
            htmlOutput =
                "<h3>"
                    + bundle.getString("response.incorrectCreds")
                    + "</h3><p>"
                    + bundle.getString("response.carefulNow")
                    + "</p>";
            log.debug("Could Not Find User: " + e.toString());
            try {
              Thread.sleep(1000);
            } catch (Exception e1) {
              log.error("Failed to Pause: " + e1.toString());
            }
          }
          conn.close();
        } else {
          htmlOutput = new String("Invalid data submitted");
          if (!validEmail) {
            htmlOutput += "" + bundle.getString("response.badEmail") + "";
          }
        }
      } catch (Exception e) {
        log.debug("Could not perform user login: " + e.toString());
        htmlOutput += "<p>" + bundle.getString("response.badRequest") + "</p>";
        try {
          Thread.sleep(1000);
        } catch (Exception e2) {
          log.error("Failed to Pause: " + e2.toString());
        }
      }
      log.debug("*** " + levelName + " End ***");
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
