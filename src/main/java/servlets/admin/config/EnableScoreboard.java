package servlets.admin.config;

import dbProcs.Getter;
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
import utils.ScoreboardStatus;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * This is the control class for enabling the the user accessible scoreboard <br>
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
public class EnableScoreboard extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(EnableScoreboard.class);

  enum ScoreboardMode {
    OPEN,
    PUBLIC,
    ADMIN_ONLY,
    CLASS_SPECIFIC,
    SELECTED_CLASS,
    INVALID
  }

  /**
   * @param classId The identifier of the class to add the players to
   * @param csrfToken
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from
    // proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("*** servlets.Admin.EnableScoreboard ***");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    HttpSession ses = request.getSession(false);
    Cookie tokenCookie = Validate.getToken(request.getCookies());
    Object tokenParmeter = request.getParameter("csrfToken");
    if (Validate.validateAdminSession(ses, tokenCookie, tokenParmeter)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      if (Validate.validateTokens(ses, tokenCookie, tokenParmeter)) {
        log.debug("An administrator is updating the scoreboard configuration");
        try {
          String applicationRoot = getServletContext().getRealPath("");
          String classId = request.getParameter("classId");
          ScoreboardMode mode = requestedMode(classId, request.getParameter("restricted"));
          String scoreboardMessage = applyMode(mode, applicationRoot, classId);
          String htmlOutput;
          if (scoreboardMessage == null) {
            log.debug("Scoreboard settings unchanged because validation failed");
            htmlOutput =
                "<h3 class='title'>Scoreboard Settings are Unchanged</h3>"
                    + "<p>Invalid data was submitted. Please try again.</p>";
          } else {
            htmlOutput =
                "<h3 class='title'>Scoreboard Settings Updated</h3><p>"
                    + scoreboardMessage
                    + "</p>";
          }
          out.write(htmlOutput);
        } catch (Exception e) {
          log.error("Could not update scoreboard configuration", e);
          out.print(
              "<h3 class=\"title\">Scoreboard Configuration Failure</h3><br>"
                  + "<p>"
                  + "<font color=\"red\">An error Occurred! Please try again.</font>"
                  + "<p>");
        }
      } else {
        log.debug("CSRF Tokens did not match");
        out.print(
            "<h3 class=\"title\">Scoreboard Configuration Failure</h3><br>"
                + "<p>"
                + "<font color=\"red\">An error Occurred! Please try again.</font>"
                + "<p>");
      }
    } else {
      out.print(
          "<h3 class=\"title\">Failure</h3><br><p><font color=\"red\">An error Occurred! Please try"
              + " non administrator functions!</font><p>");
    }
    log.debug("*** EnableScoreboard END ***");
  }

  static ScoreboardMode requestedMode(String classId, String restricted) {
    if (classId == null
        || classId.length() > 128
        || classId.codePoints().anyMatch(Character::isISOControl)) {
      return ScoreboardMode.INVALID;
    }
    if (restricted != null
        && !restricted.isEmpty()
        && !"true".equals(restricted)
        && !"false".equals(restricted)) {
      return ScoreboardMode.INVALID;
    }
    if (classId.isEmpty()) {
      if (restricted == null || restricted.isEmpty()) {
        return ScoreboardMode.OPEN;
      }
      return "true".equals(restricted) ? ScoreboardMode.ADMIN_ONLY : ScoreboardMode.PUBLIC;
    }
    if ("classSpecific".equalsIgnoreCase(classId)) {
      return restricted == null || restricted.isEmpty() || "false".equals(restricted)
          ? ScoreboardMode.CLASS_SPECIFIC
          : ScoreboardMode.INVALID;
    }
    return "true".equals(restricted) ? ScoreboardMode.ADMIN_ONLY : ScoreboardMode.SELECTED_CLASS;
  }

  private static String applyMode(ScoreboardMode mode, String applicationRoot, String classId) {
    switch (mode) {
      case OPEN:
        ScoreboardStatus.setScoreboardOpen();
        return "Scoreboard is now enabled and lists all users regardless of their class.";
      case PUBLIC:
        ScoreboardStatus.setScoreboardPublic();
        return "Scoreboard is now enabled for public view.";
      case ADMIN_ONLY:
        if (!classId.isEmpty()) {
          String[] adminClassInfo = Getter.getClassInfo(applicationRoot, classId);
          if (!classExists(adminClassInfo)) {
            return null;
          }
          ScoreboardStatus.setScoreboardAdminOnly(classId);
          return "Scoreboard is only enabled for administrators and lists users from "
              + Encode.forHtml(adminClassInfo[0])
              + ".";
        }
        ScoreboardStatus.setScoreboardAdminOnly();
        return "Scoreboard is only enabled for administrators.";
      case CLASS_SPECIFIC:
        ScoreboardStatus.setScoreboardClassSpecific();
        return "Scoreboard has been enabled and only lists users from the viewer's class. Admin"
            + " users will still see the scoreboard of the default class.";
      case SELECTED_CLASS:
        String[] classInfo = Getter.getClassInfo(applicationRoot, classId);
        if (!classExists(classInfo)) {
          return null;
        }
        ScoreboardStatus.setScoreboardClass(classId);
        return "Scoreboard has been enabled and only lists users from "
            + Encode.forHtml(classInfo[0])
            + ".";
      default:
        return null;
    }
  }

  private static boolean classExists(String[] classInfo) {
    return classInfo != null
        && classInfo.length > 0
        && classInfo[0] != null
        && !classInfo[0].isEmpty();
  }
}
