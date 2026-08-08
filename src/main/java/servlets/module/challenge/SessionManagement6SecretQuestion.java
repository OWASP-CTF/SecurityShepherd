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
 * Session Management Challenge Six - Security Question Does not return result key <br>
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
public class SessionManagement6SecretQuestion extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement6SecretQuestion.class);
  private static String levelName = "Session Management Challenge Six (Secret Question)";
  private static String levelHash =
      "b5e1020e3742cf2c0880d4098146c4dde25ebd8ceab51807bad88ff47c316ece";

  /**
   * A user submits a username and answer, these values are checked against the DB to see if they
   * are valid
   *
   * @param subEmail Sub schema user email to search DB with
   * @param subAnswer Sub schema user secret answer to check against the DB
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
            "i18n.servlets.challenges.sessionManagement.sessionManagement6", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by an authenticated session");
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      log.debug(levelName + " Servlet accessed");
      try {
        // Security questions are shared secrets, not a safe authenticator. Return the same response
        // for every email/answer pair and never turn knowledge of an answer into account access.
        String htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("question.badAnswer")
                + "</h2><p>"
                + bundle.getString("question.whoAreYou")
                + "</p>";
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

  /**
   * A user submits an email address to get that user's Secret Question. The query is parameterised
   * so the submitted email cannot alter the executed SQL.
   *
   * @param subEmail Sub schema user email to search DB with
   */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String levelName = "Session Management Challenge Six (Get Question)";
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement6", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by an authenticated session");
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      String htmlOutput = new String();
      log.debug(levelName + " Servlet accessed");
      try {
        log.debug("Getting Cookies");
        Cookie userCookies[] = request.getCookies();
        int i = 0;
        Cookie theCookie = null;
        for (i = 0; i < userCookies.length; i++) {
          if (userCookies[i].getName().compareTo("ac") == 0) {
            theCookie = userCookies[i];
            break; // End Loop, because we found the token
          }
        }
        if (theCookie != null) {
          byte[] decodedCookieBytes = Base64.decodeBase64(theCookie.getValue());
          String decodedCookie = new String(decodedCookieBytes, "UTF-8");
          log.debug("Decoded Cookie: " + decodedCookie);

          if (decodedCookie.equals("doNotReturnAnswers")) // Untampered Cookie
          {
            // Do not disclose user-specific recovery questions or whether an address exists.
            htmlOutput = bundle.getString("question.noQuestion");
          } else {
            log.debug("Tampered cookie detected");
            htmlOutput = new String(bundle.getString("response.configError"));
          }
        } else {
          log.debug("Tampered cookie detected");
          htmlOutput = new String(bundle.getString("response.configError"));
        }
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
}
