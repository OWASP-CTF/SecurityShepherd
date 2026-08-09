package servlets.module.challenge;

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
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge One <br>
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
public class SessionManagement1 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement1.class);
  private static String levelName = "Session Management Challenge One";
  public static String levelHash =
      "dfd6bfba1033fa380e378299b6a998c759646bd8aea02511482b8ce5d707f93a";
  private static String levelResult = "db7b1da5d7a43c7100a6f01bb0c";

  /** Server side session attribute holding the sub application role of this user. */
  private static final String SUB_ROLE_ATTRIBUTE = "sessionManagement1SubUserRole";

  /** The only role a sub application user is ever granted by the server. */
  private static final String DEFAULT_SUB_ROLE = "user";

  /** Privileged sub application role. Only a server side escalation may ever set this. */
  private static final String ADMIN_SUB_ROLE = "administrator";

  /**
   * The role of the sub application user is held in server side session state. The client supplied
   * "checksum" cookie is ignored, so users cannot promote themselves to administrator.
   *
   * @param upgraeUserToAdmin Red herring
   * @param returnPassword Red herring
   * @param adminDetected Red herring
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement1", locale);

    try {
      // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
      HttpSession ses = request.getSession(true);
      if (Validate.validateSession(ses)) {
        ShepherdLogManager.setRequestIp(
            request.getRemoteAddr(),
            request.getHeader("X-Forwarded-For"),
            ses.getAttribute("userName").toString());
        log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
        // The sub application role is authoritative server side state. It is never read from a
        // client controlled cookie, so the browser cannot upgrade itself to administrator
        String subUserRole = (String) ses.getAttribute(SUB_ROLE_ATTRIBUTE);
        if (subUserRole == null) {
          subUserRole = DEFAULT_SUB_ROLE;
          ses.setAttribute(SUB_ROLE_ATTRIBUTE, subUserRole);
        }
        log.debug("Sub application role for this session: " + subUserRole);
        String htmlOutput = null;
        if (ADMIN_SUB_ROLE.equals(subUserRole)) {
          log.debug("Challenge Complete");
          // Get key and add it to the output
          String userKey =
              Hash.generateUserSolution(levelResult, (String) ses.getAttribute("userName"));
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.adminClub")
                  + "</h2>"
                  + "<p>"
                  + bundle.getString("response.welcomeAdmin")
                  + "<a>"
                  + userKey
                  + "</a>"
                  + "</p>";
        }
        if (htmlOutput == null) {
          log.debug("Challenge Not Complete");
          boolean hackDetected = false;
          hackDetected =
              !(request.getParameter("adminDetected") != null
                  && request.getParameter("returnPassword") != null
                  && request.getParameter("upgradeUserToAdmin") != null);
          if (!hackDetected) {
            hackDetected =
                !(request.getParameter("adminDetected").toString().equalsIgnoreCase("false")
                    && request.getParameter("adminDetected").toString().equalsIgnoreCase("false")
                    && request.getParameter("adminDetected").toString().equalsIgnoreCase("false"));
          }

          if (!hackDetected) {
            htmlOutput =
                "<h2 class='title'>"
                    + bundle.getString("response.notAdmin")
                    + "</h2>"
                    + "<p>"
                    + bundle.getString("response.notAdminMessage")
                    + "</p>";
          } else {
            htmlOutput =
                "<h2 class='title'>"
                    + bundle.getString("response.hackDetected")
                    + "</h2>"
                    + "<p>"
                    + bundle.getString("response.hackDetectedMessage")
                    + "</p>";
          }
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } else {
        log.error(levelName + " servlet accessed with no session");
      }
    } catch (Exception e) {
      out.write(errors.getString("error.funky"));
      log.fatal(levelName + " - " + e.toString());
    }
  }
}
