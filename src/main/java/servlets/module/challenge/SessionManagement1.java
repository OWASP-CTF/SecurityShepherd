package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
  /** Name of the server side attribute holding the role this sub application serves a session. */
  private static final String roleAttribute = "sessionManagement1Role";

  /** The only role this sub application ever puts a session in. It never comes from a request. */
  private static final String defaultRole = "user";

  /**
   * Reads the role held for this session on the server, establishing it on first use.
   *
   * <p>The role has to be state the application keeps, not something the caller hands in. A cookie
   * is written by the browser and can be set to any value, so a role read out of one is a role the
   * requester chose for themselves.
   *
   * @param ses Session the request was authenticated against
   * @return The role this application has put the session in
   */
  public static String currentRole(HttpSession ses) {
    Object role = ses.getAttribute(roleAttribute);
    if (role == null) {
      role = defaultRole;
      ses.setAttribute(roleAttribute, role);
    }
    return role.toString();
  }

  /**
   * Renders the role cookie the page writes. The cookie is a copy of state the server already
   * holds, put there for the browser's convenience; nothing is decided on the way back.
   *
   * @param ses Session the cookie is being written for
   * @return The value to place in the "checksum" cookie
   */
  public static String roleCookieValue(HttpSession ses) {
    try {
      return Base64.encodeBase64String(("userRole=" + currentRole(ses)).getBytes("UTF-8"));
    } catch (java.io.UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  public static String levelHash =
      "dfd6bfba1033fa380e378299b6a998c759646bd8aea02511482b8ce5d707f93a";
  private static String levelResult = "db7b1da5d7a43c7100a6f01bb0c";

  /**
   * Users must take advance of the broken session management in this application by modifying the
   * tracking cookie "checksum" which is encoded in base 64. They must modify this cookie to be
   * equal to administrator to access the result key.
   *
   * @param upgraeUserToAdmin Red herring
   * @param returnPassword Red herring
   * @param adminDetected Red herring
   * @param checksum Cookie encoded base 64 that manages who is signed in to the sub schema
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
        // The role that decides what this request may see is read from server side session
        // state. The "checksum" cookie still travels with the request, but it is only compared
        // against what the server already knows so that tampering can be noticed and logged; it
        // is not what the decision is made on.
        String userRole = currentRole(ses);
        log.debug("Role held server side for this session: " + userRole);

        String htmlOutput = null;
        Cookie userCookies[] = request.getCookies();
        Cookie theCookie = null;
        if (userCookies != null) {
          for (int i = 0; i < userCookies.length; i++) {
            if (userCookies[i].getName().compareTo("checksum") == 0) {
              theCookie = userCookies[i];
              break; // End Loop, because we found the token
            }
          }
        }
        if (theCookie != null) {
          byte[] decodedCookieBytes = Base64.decodeBase64(theCookie.getValue());
          String decodedCookie = new String(decodedCookieBytes, "UTF-8");
          if (!decodedCookie.equals("userRole=" + userRole)) {
            log.error("Role cookie disagreed with the role held server side; the cookie is ignored");
          }
        }

        if (!defaultRole.equals(userRole)) {
          // Nothing in this sub application puts a session in any other role, so a session
          // claiming one is not a session this application issued.
          log.error(levelName + " refused a request for a role it does not serve");
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
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
