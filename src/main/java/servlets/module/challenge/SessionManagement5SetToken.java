package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
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
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Five SessionManagement5SetToken (Does not Return Result Key)
 *
 * <p>A DB call is made to check if a user exists. If the user does exist, a password reset token is
 * created and the server returns the existing acknowledgement that a reset URL was emailed.
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
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * Used to issue a token for a user's password reset request.
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
          byte[] tokenBytes = new byte[32];
          SECURE_RANDOM.nextBytes(tokenBytes);
          String resetToken = Base64.encodeBase64URLSafeString(tokenBytes);
          callstmt =
              conn.prepareStatement(
                  "UPDATE users SET resetToken = SHA2(?, 256), resetTokenExpires = ? WHERE"
                      + " userName = ?");
          callstmt.setString(1, resetToken);
          callstmt.setLong(2, System.currentTimeMillis() + 600000L);
          callstmt.setString(3, userName);
          callstmt.executeUpdate();
          callstmt = conn.prepareStatement("COMMIT");
          callstmt.execute();
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
