package servlets.module.lesson;

import java.io.IOException;
import java.io.PrintWriter;
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
 * Security Misconfiguration Lesson <br>
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
public class SecurityMisconfigLesson extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SecurityMisconfigLesson.class);
  private static String levelName = "Security Misconfig Lesson";
  public static String levelhash =
      "fe04648f43cdf2d523ecf1675f1ade2cde04a7a2e9a7f1a80dbb6dc9f717c833";

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    // Attempting to recover username of session that made request
    HttpSession ses = request.getSession(true);
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle("i18n.servlets.lessons.securityMisconfig", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      try {
        String userName = request.getParameter("userName");
        log.debug("User Name - " + userName);
        // A credential published with the application authenticates nobody, so no submission
        // reaches an administrator branch here.
        log.debug(levelName + " does not accept the credential it used to ship with");
        String htmlOutput = new String();
        if (userName.contentEquals("admin")) {
          htmlOutput = bundle.getString("response.incorrectPassword");
        } else {
          htmlOutput =
              bundle.getString("response.noUserFound") + " \"" + Encode.forHtml(userName) + "\"";
        }
        htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("response.authError")
                + "</h2><p>"
                + htmlOutput
                + "</p>";
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
      out.write(errors.getString("error.noSession"));
    }
  }
}
