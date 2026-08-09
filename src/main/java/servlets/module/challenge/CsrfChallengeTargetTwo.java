package servlets.module.challenge;

import dbProcs.Getter;
import dbProcs.Setter;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Cross Site Request Forgery Challenge Target Two - Does not return Result key <br>
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
public class CsrfChallengeTargetTwo extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(CsrfChallengeTargetTwo.class);
  private static String levelName = "CSRF 2 Target";

  /**
   * CSRF vulnerable function that can be used by users to force other users to mark their CSRF
   * challenge Two as complete.
   *
   * @param userId User identifier to be incremented
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("Cross-SiteForegery Challenge Two Target Servlet");

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);

    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    try {
      boolean result = false;
      HttpSession ses = request.getSession(true);
      if (Validate.validateSession(ses)) {
        ShepherdLogManager.setRequestIp(
            request.getRemoteAddr(),
            request.getHeader("X-Forwarded-For"),
            ses.getAttribute("userName").toString());
        log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
        String plusId = request.getParameter("userId");
        log.debug("User Submitted - " + plusId);
        // Validate against the application's own session-bound CSRF cookie (the same
        // cookie/parameter pair every other authenticated call in this app relies on), rather
        // than a token minted ad hoc by this servlet - a forged cross-origin request can supply
        // a userId parameter but has no way to read the victim's CSRF cookie to produce a
        // matching csrfToken parameter.
        Cookie tokenCookie = Validate.getToken(request.getCookies());
        if (!Validate.validateTokens(tokenCookie, request.getParameter("csrfToken"))) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        String userId = (String) ses.getAttribute("userStamp");
        // Only ever credit the account that is actually making this request. Trusting an
        // attacker-supplied target id let anyone mark the challenge complete for a victim who
        // never made a legitimate same-origin submission themselves - a valid token proves the
        // request is same-origin, not that the caller may act on someone else's behalf.
        if (!userId.equals(plusId)) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        String applicationRoot = getServletContext().getRealPath("");
        log.debug("Attempting to Increment ");
        String moduleHash = CsrfChallengeTwo.getLevelHash();
        String moduleId = Getter.getModuleIdFromHash(applicationRoot, moduleHash);
        result = Setter.updateCsrfCounter(applicationRoot, moduleId, userId);

        if (result) {
          out.write(csrfGenerics.getString("target.incrementSuccess"));
        } else {
          out.write(csrfGenerics.getString("target.incrementFailed"));
        }
      } else {
        out.write(csrfGenerics.getString("target.noSession"));
      }
    } catch (Exception e) {
      out.write(errors.getString("error.funky"));
      log.fatal("Cross Site Request Forgery Target Challenge 2 - " + e.toString());
    }
  }
}
