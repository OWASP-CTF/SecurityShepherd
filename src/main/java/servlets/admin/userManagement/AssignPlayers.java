package servlets.admin.userManagement;

import dbProcs.Getter;
import dbProcs.Setter;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
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
 * This is the control class for the Assign Players to Class functionality <br>
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
public class AssignPlayers extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(AssignPlayers.class);

  /**
   * Initiated by assignPlayers.jsp. A number of players can be assigned to a new class. Changing
   * the actual class of the player is handed by Setter.changePlayerClass
   *
   * @param classId The identifier of the class to add the players to
   * @param players[] An array of player identifiers to add to the specified class
   * @param csrfToken
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("*** servlets.Admin.AssignPlayers ***");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    response.setCharacterEncoding("UTF-8");
    request.setCharacterEncoding("UTF-8");
    HttpSession ses = request.getSession(false);
    Cookie tokenCookie = Validate.getToken(request.getCookies());
    Object tokenParmeter = request.getParameter("csrfToken");
    if (Validate.validateAdminSession(ses, tokenCookie, tokenParmeter)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      if (Validate.validateTokens(ses, tokenCookie, tokenParmeter)) {
        boolean notNull = false;
        boolean validPlayer = false;
        String[] classInfo = new String[2];
        try {
          log.debug("Getting ApplicationRoot");
          String ApplicationRoot = getServletContext().getRealPath("");
          log.debug("Servlet root = " + ApplicationRoot);

          log.debug("Getting Parameters");
          String classId = request.getParameter("classId");
          String[] players = request.getParameterValues("players[]");

          // Validation
          notNull = players != null && players.length > 0 && players.length <= 1000;
          log.debug("Ensuring strings are not empty");
          if (classId != null && classId.isEmpty()) {
            log.debug("classId is empty; nulling");
            classId = null;
          }
          if (notNull) {
            if (classId != null) {
              classInfo = Getter.getClassInfo(ApplicationRoot, classId);
              if (classInfo == null
                  || classInfo.length < 2
                  || classInfo[0] == null
                  || classInfo[0].isEmpty()) {
                classId = null;
                notNull = false;
              }
            }
            if (classId == null && notNull) {
              classInfo[1] = "Unassigned";
              classInfo[0] = "Players";
            }
            validPlayer = notNull;
            for (String player : players) {
              if (player == null
                  || player.isEmpty()
                  || !Getter.findPlayerById(ApplicationRoot, player)) {
                validPlayer = false;
                break;
              }
            }
          }
          if (notNull && validPlayer) {
            // Data is good, Add user
            log.debug("Updating Player Class");
            String reponseMessage = new String();
            for (int i = 0; i < players.length; i++) {
              String userName = new String();
              if (classId != null) {
                userName = Setter.updatePlayerClass(ApplicationRoot, classId, players[i]);
              } else {
                userName = Setter.updatePlayerClassToNull(ApplicationRoot, players[i]);
              }
              if (userName != null) {
                reponseMessage +=
                    "<a>"
                        + Encode.forHtml(userName)
                        + "</a> assigned successfully to <a>"
                        + Encode.forHtml(classInfo[1] + " " + classInfo[0])
                        + "</a>.<br>";
              } else {
                reponseMessage +=
                    "<font color='red'>User could not be updated. Please try again.</font><br/>";
              }
            }
            out.print(
                "<h3 class=\"title\">Player Assignment Result</h3>"
                    + "<p>"
                    + reponseMessage
                    + "<p>");
          } else {
            // Validation Error Responses
            String errorMessage = "An Error Occurred: ";
            if (!notNull) {
              log.error("Null values detected");
              errorMessage += "Invalid Request. Please try again";
            } else if (!validPlayer) {
              log.error("Player not found");
              errorMessage += "Player(s) Not Found. Please try again";
            }
            out.print(
                "<h3 class=\"title\">Player Assignment Failure</h3>"
                    + "<p><font color=\"red\">"
                    + Encode.forHtml(errorMessage)
                    + "</font><p>");
          }
        } catch (Exception e) {
          log.error("Assign Players Error: " + e.toString());
          out.print(
              "<h3 class=\"title\">Player Assignment Failure</h3>"
                  + "<p>"
                  + "<font color=\"red\">An error Occurred! Please try again.</font>"
                  + "<p>");
        }
      } else {
        log.debug("CSRF Tokens did not match");
        out.print(
            "<h3 class=\"title\">Player Assignment Failure</h3>"
                + "<p>"
                + "<font color=\"red\">An error Occurred! Please try again.</font>"
                + "<p>");
      }
    } else {
      out.print(
          "<h3 class=\"title\">Player Assignment Failure</h3><p><font color=\"red\">An error"
              + " Occurred! Please try non administrator functions!</font><p>");
    }
    log.debug("*** AssignPlayers END ***");
  }
}
