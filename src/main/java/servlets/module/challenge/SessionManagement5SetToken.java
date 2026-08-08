package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Five SessionManagement5SetToken (Does not Return Result Key)
 *
 * <p>This function is a shell to give the appearance that a token has been set for a user. A DB
 * call is made to check if a user exists. If the user does exist the server returns an ok message
 * claiming that the user has been emailed a URL with a token embedded for resetting their password.
 * This in fact does not happen. User must find another way to sign in as an admin.
 *
 * <p><br>
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
public class SessionManagement5SetToken extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5SetToken.class);
  private static String levelName = "SessionManagement5SetToken";
  public static String levelHash = SessionManagement5.levelHash;

  /** Lifetime of an issued password reset token, in milliseconds. */
  private static final long TOKEN_LIFETIME_MILLIS = 10L * 60L * 1000L;

  /** Server side store of the outstanding reset token for each user. */
  private static final Map<String, String> issuedTokens = new ConcurrentHashMap<String, String>();

  /** Expiry instant of the outstanding reset token for each user. */
  private static final Map<String, Long> tokenExpiry = new ConcurrentHashMap<String, Long>();

  private static final SecureRandom secureRandom = new SecureRandom();

  /**
   * Issues an unguessable, single use password reset token bound to one user. The token is kept
   * server side and is never derived from the clock, so it cannot be forged by a caller.
   *
   * @param userName the account the token is issued for
   * @return the freshly generated token
   */
  public static String issueToken(String userName) {
    byte[] raw = new byte[32];
    secureRandom.nextBytes(raw);
    String token = Base64.encodeBase64URLSafeString(raw);
    issuedTokens.put(userName, token);
    tokenExpiry.put(userName, Long.valueOf(System.currentTimeMillis() + TOKEN_LIFETIME_MILLIS));
    return token;
  }

  /**
   * Verifies a reset token against the one issued for that user and consumes it, so a token is
   * valid at most once and only for the account it was issued to.
   *
   * @param userName the account whose password is being reset
   * @param token the token presented by the caller
   * @return true only when the token was issued for this user and has not expired
   */
  public static boolean consumeToken(String userName, String token) {
    if (userName == null || token == null || token.isEmpty()) {
      return false;
    }
    String expected = issuedTokens.remove(userName);
    Long expires = tokenExpiry.remove(userName);
    if (expected == null || expires == null) {
      return false;
    }
    boolean live = System.currentTimeMillis() < expires.longValue();
    boolean match =
        MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8));
    return live && match;
  }

  /**
   * Used to apparently send a message to a user with a token to reset their password.
   *
   * @param userName Sub schema user name
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
      try {
        log.debug("Getting Parameters");
        Object nameObj = request.getParameter("subUserName");
        String userName = new String();
        if (nameObj != null) {
          userName = (String) nameObj;
        }
        log.debug("subName = " + userName);

        log.debug("Getting ApplicationRoot");
        String ApplicationRoot = getServletContext().getRealPath("");
        log.debug("Servlet root = " + ApplicationRoot);

        Connection conn =
            Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalFive");
        log.debug("Checking name");
        PreparedStatement callstmt;

        log.debug("Committing changes made to database");
        callstmt = conn.prepareStatement("COMMIT");
        callstmt.execute();
        log.debug("Changes committed.");

        callstmt = conn.prepareStatement("SELECT userName FROM users WHERE userName = ?");
        callstmt.setString(1, userName);
        log.debug("Executing findUser");
        ResultSet resultSet = callstmt.executeQuery();
        // Is the username valid?
        if (resultSet.next()) {
          log.debug("User found");
          issueToken(userName);
          htmlOutput =
              bundle.getString("setToken.sentTo.1")
                  + " '"
                  + Encode.forHtml(userName)
                  + "' "
                  + bundle.getString("setToken.sentTo.2");
        } else {
          log.debug("User not Found");
          htmlOutput = bundle.getString("response.badUser") + "" + Encode.forHtml(userName);
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
}
