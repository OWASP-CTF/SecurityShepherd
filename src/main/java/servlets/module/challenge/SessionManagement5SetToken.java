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

        // Anyone may ask for a reset, so answering "user not found" for one name and "token sent"
        // for another turns this into a free oracle for which accounts exist — the first step of
        // targeting the admin account this level's sign-in form checks for. The reply is now the
        // same whatever was submitted, which also means there is nothing left to look up: no token
        // is sent from here, and the account is not needed in order to say so.
        htmlOutput =
            bundle.getString("setToken.sentTo.1")
                + " '"
                + Encode.forHtml(userName)
                + "' "
                + bundle.getString("setToken.sentTo.2");
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
