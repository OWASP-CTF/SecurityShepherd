package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
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
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Security Misconfiguration Steal Tokens <br>
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
public class SecurityMisconfigStealTokens extends HttpServlet {

  // Security Misconfiguration Challenge
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SecurityMisconfigStealTokens.class);
  private static String levelName = "Security Misconfig Cookie Flags Servlet";
  public static String levelHash =
      "c4285bbc6734a10897d672c1ed3dd9417e0530a4e0186c27699f54637c7fb5d4";

  /**
   * This servlet reports on the identity token presented with the request. Possession of a token is
   * never accepted as proof of identity: the only token this session may act with is the token
   * bound to the session's own user.
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.securityMisconfig.stealTokens", locale);

      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      try {
        String applicationRoot = getServletContext().getRealPath("");

        // Identity comes from the server side session, never from a cookie value that anybody
        // could have copied from another user
        String userId = ses.getAttribute("userStamp").toString();
        String userActualCookie = getUserToken(userId, applicationRoot);

        // Getting Submitted Cookie. It may be absent: the cookie is flagged Secure and is not
        // presented over a plain text connection
        Cookie theToken = null;
        Cookie[] userCookies = request.getCookies();
        if (userCookies != null) {
          for (int i = 0; i < userCookies.length; i++) {
            if (userCookies[i].getName().compareTo("securityMisconfigLesson") == 0) {
              theToken = userCookies[i];
              break; // End Loop, because we found the token
            }
          }
        }
        String cookieValue = (theToken == null) ? new String() : theToken.getValue();

        // Possession of a token is not proof of identity. The only token this session may act
        // with is the token bound to the session's own user, compared in constant time.
        boolean ownToken =
            !cookieValue.isEmpty()
                && !userActualCookie.isEmpty()
                && MessageDigest.isEqual(
                    cookieValue.getBytes(StandardCharsets.UTF_8),
                    userActualCookie.getBytes(StandardCharsets.UTF_8));

        if (ownToken) {
          // User is using their own Cookie: Not Complete
          htmlOutput =
              new String(
                  "<h2 class='title'>"
                      + bundle.getString("securityMisconfig.servlet.stealTokens.notComplete")
                      + "</h2>"
                      + "<p>"
                      + bundle.getString(
                          "securityMisconfig.servlet.stealTokens.notComplete.message")
                      + "<p>");
        } else {
          // A token that is not bound to this session proves nothing and is rejected
          log.error(
              levelName
                  + " rejected a token that is not bound to the session user: "
                  + ses.getAttribute("userName").toString());
          htmlOutput =
              new String(
                  "<h2 class='title'>"
                      + bundle.getString("securityMisconfig.servlet.stealTokens.notComplete")
                      + "</h2>"
                      + "<p>"
                      + bundle.getString(
                          "securityMisconfig.servlet.stealTokens.notComplete.yourToken")
                      + "<p>");
        }
      } catch (Exception e) {
        out.write(errors.getString("error.detected"));
        log.fatal(levelName + " - " + e.toString());
      }
      log.debug("Outputting HTML");
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /**
   * Method that will return a users token. If the user does not have a token, this will set one.
   *
   * @param userId User Identifier to search for
   * @param applicationRoot Running context of application
   * @return The token associated with the submitted userId
   * @throws SQLException
   */
  public static String getUserToken(String userId, String applicationRoot) throws SQLException {
    String userToken = new String();
    log.debug("Getting user token with id: " + userId);
    Connection conn =
        Database.getChallengeConnection(applicationRoot, "SecurityMisconfigStealToken");
    try {
      CallableStatement getTokenCs = conn.prepareCall("call getToken(?)");
      getTokenCs.setString(1, userId);
      log.debug("Executing getToken procedure...");
      ResultSet tokenRs = getTokenCs.executeQuery();
      if (tokenRs.next()) {
        userToken = tokenRs.getString(1);
      } else {
        log.error("No Results From Call");
        throw new SQLException("No results from getToken Call. Empty Result Set");
      }
      tokenRs.close();
    } catch (SQLException e) {
      log.error("Could not get user SecurityMisconfigStealToken token: " + e.toString());
      throw e;
    }
    conn.close();
    if (!userToken.isEmpty()) {
      log.debug("Retrieved the token of the requesting user");
    }
    return userToken;
  }
}
