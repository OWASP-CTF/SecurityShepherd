package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
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
 * Session Management Challenge Eight <br>
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
public class SessionManagement8 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement8.class);
  private static String levelName = "Session Management Challenge Eight";
  /** Name of the server side attribute holding the role this sub application serves a session. */
  private static final String roleAttribute = "sessionManagement8Role";

  /** Name of the server side attribute holding the marker written into the role cookie. */
  private static final String roleCookieAttribute = "sessionManagement8RoleCookie";

  /** The only role this sub application ever puts a session in. It never comes from a request. */
  private static final String defaultRole = "user";

  /**
   * Reads the role held for this session on the server, establishing it on first use.
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
   * Issues the marker the page writes into the role cookie.
   *
   * <p>The cookie used to carry a constant string that was the same in every deployment and for
   * every visitor, and matching it was the whole of the check. A value that is fixed and unsigned
   * is a value anybody can produce, so the marker is now drawn from a CSPRNG per session and is
   * only ever compared against the copy kept here. The role itself is not in the cookie at all.
   *
   * @param ses Session the marker is being issued to
   * @return The value to place in the challengeRole cookie
   */
  public static String issueRoleCookieValue(HttpSession ses) {
    currentRole(ses);
    String marker = Hash.randomString();
    ses.setAttribute(roleCookieAttribute, marker);
    return marker;
  }

  private static String levelHash =
      "714d8601c303bbef8b5cabab60b1060ac41f0d96f53b6ea54705bb1ea4316334";

  /**
   * Users must take advance of the broken session management in this application by modifying the
   * tracking cookie "challengeRole" which is encoded in ATOM-128. They must modify this cookie to
   * be equal to superuser to access the result key.
   *
   * @param returnUserRole Red herring
   * @param returnPassword Red herring
   * @param adminDetected Red herring
   * @param challengeRole Cookie encoded ATOM-128 that manages who is signed in to the sub schema
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String redherringOne = new String("returnUserRole");
    String redherringTwo = new String("returnPassword");
    String redherringThr = new String("adminDetected");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement8", locale);

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
        // What this request may see is decided by the role held on the server. The cookie
        // carries an opaque per session marker and is compared only against the copy kept here,
        // in constant time, so that tampering can be noticed; no value in it grants anything.
        String userRole = currentRole(ses);
        log.debug("Role held server side for this session: " + userRole);

        Cookie userCookies[] = request.getCookies();
        Cookie theCookie = null;
        if (userCookies != null) {
          for (int i = 0; i < userCookies.length; i++) {
            if (userCookies[i].getName().compareTo("challengeRole") == 0) {
              theCookie = userCookies[i];
              break; // End Loop, because we found the token
            }
          }
        }
        String htmlOutput = new String();
        if (theCookie != null) {
          Object issuedMarker = ses.getAttribute(roleCookieAttribute);
          boolean untampered =
              issuedMarker != null
                  && MessageDigest.isEqual(
                      issuedMarker.toString().getBytes(StandardCharsets.UTF_8),
                      theCookie.getValue().getBytes(StandardCharsets.UTF_8));
          if (!untampered) {
            log.debug("Tampered role cookie detected");
            htmlOutput += "<!-- " + bundle.getString("response.invalidRole") + " -->";
          } else {
            log.debug("No change to role cookie submitted");
          }
        } else {
          log.debug("No Role Cookie Submitted");
        }

        if (!defaultRole.equals(userRole)) {
          // Nothing in this sub application puts a session in any other role, so a session
          // claiming one is not a session this application issued.
          log.error(levelName + " refused a request for a role it does not serve");
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        if (htmlOutput.isEmpty()) {
          log.debug("Challenge Not Complete");
          boolean hackDetected = false;
          hackDetected =
              !(request.getParameter(redherringOne) != null
                  && request.getParameter(redherringTwo) != null
                  && request.getParameter(redherringThr) != null);
          if (!hackDetected) {
            String paramOne = request.getParameter(redherringOne).toString();
            String paramTwo = request.getParameter(redherringTwo).toString();
            String paramThr = request.getParameter(redherringThr).toString();
            log.debug("Param value of " + redherringOne + ":" + paramOne);
            log.debug("Param value of " + redherringTwo + ":" + paramTwo);
            log.debug("Param value of " + redherringThr + ":" + paramThr);
            hackDetected =
                !(paramOne.equalsIgnoreCase("false")
                    && paramTwo.equalsIgnoreCase("false")
                    && paramThr.equalsIgnoreCase("false"));
          }
          if (!hackDetected) {
            htmlOutput =
                "<h2 class='title'>"
                    + bundle.getString("response.notPrivileged")
                    + "</h2>"
                    + "<p>"
                    + bundle.getString("response.notPrivileged.message")
                    + "</p>";
          } else {
            htmlOutput =
                "<h2 class='title'>"
                    + bundle.getString("response.hackDetected")
                    + "</h2>"
                    + "<p>"
                    + bundle.getString("response.hackDetected.message")
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
