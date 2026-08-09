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
 * Session Management Challenge Four <br>
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
public class SessionManagement4 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement4.class);
  private static String levelName = "Session Management Challenge Four";

  /** Name of the server side attribute holding the sub session issued to this session. */
  private static final String subSessionAttribute = "sessionManagement4SubSession";

  /**
   * Issues an identifier for this challenge's sub session and records it on the server.
   *
   * <p>The identifier used to be a counter written out in decimal and wrapped in two rounds of
   * base64. Encoding is not secrecy: unwrapping it costs nothing, and once unwrapped the
   * neighbouring sessions are the neighbouring numbers. This one comes from a CSPRNG, so knowing
   * any number of identifiers says nothing about the next, and it is only ever meaningful by
   * comparison against the copy held here.
   *
   * @param ses Session the sub session is being issued to
   * @return The identifier to place in the SubSessionID cookie
   */
  public static String issueSubSession(HttpSession ses) {
    String subSessionId = Hash.randomString();
    ses.setAttribute(subSessionAttribute, subSessionId);
    return subSessionId;
  }

  public static String levelHash =
      "ec43ae137b8bf7abb9c85a87cf95c23f7fadcf08a092e05620c9968bd60fcba6";
  private static String levelResult = "238a43b12dde07f39d14599a780ae90f87a23e";

  /**
   * Users must discover the session id for this sub application is very weak. The default session
   * ID for a guest will be 00000001 base64'd. The admin's session will be 00000021
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
            "i18n.servlets.challenges.sessionManagement.sessionManagement4", locale);

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
        Cookie userCookies[] = request.getCookies();
        Cookie theCookie = null;
        if (userCookies != null) {
          for (int i = 0; i < userCookies.length; i++) {
            if (userCookies[i].getName().compareTo("SubSessionID") == 0) {
              theCookie = userCookies[i];
              break; // End Loop, because we found the token
            }
          }
        }
        String htmlOutput = null;
        if (theCookie != null) {
          // The identifier is only ever meaningful by comparison against the one this
          // application issued for this session and kept. It is compared whole and in constant
          // time, so a caller learns nothing from how long the answer took, and because it was
          // drawn from a CSPRNG rather than counted up, a neighbouring session cannot be reached
          // by adding one to your own.
          Object issuedSubSession = ses.getAttribute(subSessionAttribute);
          if (issuedSubSession != null
              && MessageDigest.isEqual(
                  issuedSubSession.toString().getBytes(StandardCharsets.UTF_8),
                  theCookie.getValue().getBytes(StandardCharsets.UTF_8))) {
            log.debug("Live Session Detected");
          } else {
            log.debug("Dead Session Detected");
          }
        }
        if (htmlOutput == null) {
          log.debug("Challenge Not Complete");
          boolean hackDetected = false;
          hackDetected =
              !(request.getParameter("useSecurity") != null
                  && request.getParameter("userId") != null);
          if (!hackDetected) {
            log.debug("useSecurity: " + request.getParameter("useSecurity"));
            log.debug("userId: " + request.getParameter("userId"));
            hackDetected =
                !(request.getParameter("useSecurity").toString().equalsIgnoreCase("true"));
          } else {
            log.debug("Parameters Missing");
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
