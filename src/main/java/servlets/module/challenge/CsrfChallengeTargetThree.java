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
 * Cross Site Request Forgery challenge Target Three - Does not return result key <br>
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
public class CsrfChallengeTargetThree extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(CsrfChallengeTargetThree.class);
  private static String levelName = "CSRF 3 Target";

  /**
   * Increments the requesting user's own CSRF-3 counter, but only when the request carries a
   * csrfToken that matches the token bound to the requester's own session. The endpoint never
   * mutates any account other than the one making the request.
   *
   * @param userId User identifier to be incremented
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("Cross-SiteForegery Challenge Three Target");

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
        String plusId = request.getParameter("userid");
        log.debug("User Submitted - " + plusId);
        // Two things were wrong here. (1) The submitted csrfToken was only checked for being
        // present/non-empty, never compared against anything - so it provided zero protection;
        // any placeholder string satisfied it. (2) Even a *real* per-session token only proves
        // who is making the request, it says nothing about whether that requester is allowed to
        // mutate someone else's counter - a caller acting with their own perfectly legitimate
        // token could still target an arbitrary "userid" belonging to a different account. This
        // "increment whoever you like" capability is exactly what made the endpoint worth
        // forging a cross-site request against in the first place, so closing it means the
        // requester's own verified token can only ever affect the requester's own counter.
        Cookie tokenCookie = Validate.getToken(request.getCookies());
        Object tokenParameter = request.getParameter("csrfToken");
        boolean validCsrfToken = Validate.validateTokens(tokenCookie, tokenParameter);

        String userId = (String) ses.getAttribute("userStamp");
        boolean actingOnOwnAccount = userId.equals(plusId);
        if (validCsrfToken && actingOnOwnAccount) {
          log.debug("Attempting to Increment ");
          String ApplicationRoot = getServletContext().getRealPath("");
          String moduleHash = CsrfChallengeThree.getLevelHash();
          String moduleId = Getter.getModuleIdFromHash(ApplicationRoot, moduleHash);
          result = Setter.updateCsrfCounter(ApplicationRoot, moduleId, userId);
        } else if (!actingOnOwnAccount) {
          log.error(
              "Refusing to let '" + userId + "' modify another user's ('" + plusId + "') counter");
        } else {
          log.debug("No valid CSRF Token found");
        }

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
      log.fatal("Cross Site Request Forgery Challenge Target 3 - " + e.toString());
    }
  }
}
