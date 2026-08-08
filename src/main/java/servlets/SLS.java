package servlets;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import java.io.IOException;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.CsrfToken;
import utils.LoginMethod;
import utils.ShepherdLogManager;

/**
 * Control class for the SSO logout operation <br>
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
public class SLS extends HttpServlet {

  private static final long serialVersionUID = -5824919455464886874L;
  private static final Logger log = LogManager.getLogger(SLS.class);

  /**
   * Initiated in index.jsp. Invalidates session and Security Shepherd tokens are removed. The user
   * is logged out.
   *
   * @param csrfToken
   */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    handleRequest(request, response);
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    handleRequest(request, response);
  }

  private void handleRequest(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from
    // proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("**** servlets.SLS ***");
    response.setCharacterEncoding("UTF-8");
    request.setCharacterEncoding("UTF-8");
    if (!LoginMethod.isSaml()) {
      response.sendRedirect("../login.jsp");
      return;
    }

    Auth auth;
    try {
      auth = new Auth(request, response);
    } catch (SettingsException e) {
      throw new ServletException("SAML is not configured", e);
    } catch (Error e) {
      throw new ServletException("Could not initialize SAML logout", e);
    }

    try {
      // The toolkit validates the signed SAML logout message. This endpoint is a protocol callback,
      // so it cannot depend on the application session or CSRF token that SP-initiated logout has
      // already invalidated.
      auth.processSLO();
    } catch (Exception e) {
      throw new ServletException("Could not process SAML logout", e);
    }

    List<String> errors = auth.getErrors();
    if (!errors.isEmpty()) {
      log.warn("SAML logout validation failed: {}", StringUtils.join(errors, ", "));
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid SAML logout response");
      return;
    }

    HttpSession session = request.getSession(false);
    if (session != null) {
      session.invalidate();
    }
    CsrfToken.expire(request, response);
    log.debug("SSO logout completed");
    if (!response.isCommitted()) {
      response.sendRedirect("../login.jsp");
    }
    log.debug("*** END SLS ***");
  }
}
