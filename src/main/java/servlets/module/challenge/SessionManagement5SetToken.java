package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
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

  /** Server side password reset state. The token itself never leaves the server. */
  public static final String RESET_TOKEN_HASH_ATTRIBUTE = "sessionManagement5ResetTokenHash";

  public static final String RESET_USER_ATTRIBUTE = "sessionManagement5ResetUserName";

  public static final String RESET_EXPIRY_ATTRIBUTE = "sessionManagement5ResetExpiry";

  /** Reset tokens expire after ten minutes, as advertised to the user. */
  public static final long RESET_TOKEN_LIFETIME_MILLIS = 10L * 60L * 1000L;

  private static final SecureRandom secureRandom = new SecureRandom();

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
          // Issue a single use, unguessable reset token. Only its digest is retained, in server
          // side session state, and the token itself is delivered out of band (email) - it is
          // never returned to the caller and can never be derived from the clock.
          byte[] tokenBytes = new byte[32];
          secureRandom.nextBytes(tokenBytes);
          String resetToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
          ses.setAttribute(RESET_TOKEN_HASH_ATTRIBUTE, sha256Hex(resetToken));
          ses.setAttribute(RESET_USER_ATTRIBUTE, resultSet.getString(1));
          ses.setAttribute(
              RESET_EXPIRY_ATTRIBUTE,
              Long.valueOf(System.currentTimeMillis() + RESET_TOKEN_LIFETIME_MILLIS));
          log.debug("Password reset token issued and emailed to the account owner");
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

  /**
   * Digests a password reset token so that only its hash is held in server side session state.
   *
   * @param token The reset token to digest
   * @return Lower case hexadecimal SHA-256 digest of the token
   * @throws NoSuchAlgorithmException If SHA-256 is unavailable
   */
  public static String sha256Hex(String token) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
    StringBuilder builder = new StringBuilder();
    for (byte hashByte : hashBytes) {
      builder.append(String.format("%02x", hashByte));
    }
    return builder.toString();
  }
}
