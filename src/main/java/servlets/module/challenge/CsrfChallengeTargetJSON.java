package servlets.module.challenge;

import dbProcs.Getter;
import dbProcs.Setter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Scanner;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Cross Site Request Forgery Challenge Target SON - Does not return Result key <br>
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
public class CsrfChallengeTargetJSON extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(CsrfChallengeTargetJSON.class);
  private static String levelName = "CSRF JSON Target";

  /**
   * CSRF vulnerable function that can be used by users to force other users to mark their CSRF
   * challenge as complete. Function expecting JSON formed data
   *
   * @param userId User identifier to be incremented
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug(levelName + " Servlet");

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);

    response.setContentType("text/html");
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

        // Require a non-simple JSON content type. A cross-site page can auto-submit a simple form
        // POST, but it cannot set application/json without triggering a pre-flighted CORS request,
        // so rejecting anything else removes the forgeable form-post entry point.
        String contentType = request.getContentType();
        if (contentType == null || !contentType.toLowerCase().contains("application/json")) {
          response.sendError(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
          return;
        }

        log.debug("Getting JSON String");
        String jsonData = extractPostRequestBody(request);
        log.debug("POST body: " + jsonData);
        JSONObject json = new JSONObject(jsonData);
        log.debug("Getting userId");
        String plusId = (String) json.get("userId");
        log.debug("User Submitted - " + plusId);
        Cookie tokenCookie = Validate.getToken(request.getCookies());
        Object tokenParmeter = json.optString("csrfToken", request.getParameter("csrfToken"));
        // The state change rode on the session cookie alone, so an off-site page could trigger it
        // in the victim's browser. Require the per-session anti-CSRF token, which a cross-site
        // request cannot read, before performing the counter increment.
        if (!Validate.validateTokens(tokenCookie, tokenParmeter)) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        String userId = (String) ses.getAttribute("userStamp");
        // Only the token-bearing owner of this session may increment their own counter; nothing in
        // a request naming another user establishes that user's intent.
        if (!userId.equals(plusId)) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        String applicationRoot = getServletContext().getRealPath("");
        String moduleHash = CsrfChallengeJSON.getLevelHash();
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
      log.fatal(levelName + " - " + e.toString());
    }
  }

  @SuppressWarnings("resource")
  static String extractPostRequestBody(HttpServletRequest request) throws IOException {
    if ("POST".equalsIgnoreCase(request.getMethod())) {
      Scanner s = new Scanner(request.getInputStream(), "UTF-8").useDelimiter("\\A");
      return s.hasNext() ? s.next() : "";
    }
    return "";
  }
}
