package servlets;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import dbProcs.Getter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.CsrfToken;
import utils.ShepherdLogManager;
import utils.UserKicker;

/**
 * Control class for the authentication procedure. <br>
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
public class ACS extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(ACS.class);

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("**** servlets.ACS ***");
    response.setCharacterEncoding("UTF-8");
    request.setCharacterEncoding("UTF-8");
    HttpSession ses = request.getSession(true);

    Object language = ses.getAttribute("lang");

    String errorMessage = new String();

    request.setCharacterEncoding("UTF-8");

    response.setContentType("text/plain");

    log.debug("Getting ApplicationRoot");
    String ApplicationRoot = getServletContext().getRealPath("");
    log.debug("Servlet root = " + ApplicationRoot);

    boolean mustRedirect = false;
    boolean ssoValid = false;

    // Start SAML processing

    log.debug("Processing SAML data...");

    Auth auth;
    try {
      auth = new Auth(request, response);
    } catch (SettingsException e) {
      throw new RuntimeException("SAML not configured: " + e.toString());
    } catch (Error e) {
      throw new RuntimeException("SAML error : " + e.toString());
    }

    try {
      auth.processResponse();
    } catch (Exception e) {
      throw new RuntimeException("SAML error when processing response: " + e.toString());
    }

    log.debug("SAML data processed");

    if (!auth.isAuthenticated()) {
      log.debug("User not authenticated");

      errorMessage += "Not authenticated";
      ses.setAttribute("loginFailed", errorMessage);
      response.sendRedirect("../login.jsp");

    } else {
      log.debug("User authenticated");
      List<String> errors = auth.getErrors();
      if (!errors.isEmpty()) {
        errorMessage += StringUtils.join(errors, ", ");
        log.debug("SAML errors found: " + StringUtils.join(errors, ", "));
      } else {
        Map<String, List<String>> attributes = auth.getAttributes();
        String nameId = auth.getNameId();
        String nameIdFormat = auth.getNameIdFormat();
        String sessionIndex = auth.getSessionIndex();
        String nameidNameQualifier = auth.getNameIdNameQualifier();
        String nameidSPNameQualifier = auth.getNameIdSPNameQualifier();

        ses.setAttribute("attributes", attributes);
        ses.setAttribute("nameId", nameId);
        ses.setAttribute("nameIdFormat", nameIdFormat);
        ses.setAttribute("sessionIndex", sessionIndex);

        ses.setAttribute("nameidNameQualifier", nameidNameQualifier);
        ses.setAttribute("nameidSPNameQualifier", nameidSPNameQualifier);

        if (attributes.isEmpty()) {
          errorMessage += "You don't have any attributes";
          log.debug("No SAML attributes found");

        } else {
          log.debug("Unpacking SAML attributes...");

          String ssoName = null;
          String userName = null;
          String userRole = null;

          ClassLoader classLoader = getClass().getClassLoader();

          log.debug("Loading saml unpack properties file");

          String unpackFileName = "sso.properties";

          try (InputStream inputStream = classLoader.getResourceAsStream(unpackFileName)) {
            if (inputStream != null) {
              Properties prop = new Properties();
              prop.load(inputStream);
              log.debug("Saml unpack properties file loaded, unpacking saml data");

              ssoName = firstAttribute(attributes, prop.getProperty("sso.saml.ssoName"));
              userName = firstAttribute(attributes, prop.getProperty("sso.saml.userName"));
              List<String> affiliations =
                  attributeValues(attributes, prop.getProperty("sso.saml.affiliation"));
              List<String> adminAffiliations =
                  configuredAffiliations(prop.getProperty("sso.saml.adminAffiliation"));
              List<String> playerAffiliations =
                  configuredAffiliations(prop.getProperty("sso.saml.playerAffiliation"));

              if (ssoName != null && userName != null) {
                if (!Collections.disjoint(affiliations, adminAffiliations)) {
                  userRole = "admin";
                  ssoValid = true;
                } else if (!Collections.disjoint(affiliations, playerAffiliations)) {
                  userRole = "player";
                  ssoValid = true;
                }
              }
              if (!ssoValid) {
                errorMessage += "SSO authorization failed. ";
              }
            } else {
              String errorMsg =
                  "SAML unpack properties file '" + unpackFileName + "' not found in the classpath";
              log.error(errorMsg);
              throw new RuntimeException(errorMsg);
            }
          } catch (IOException e) {
            String errorMsg =
                "SAML unpack properties file '" + unpackFileName + "' cannot be loaded";

            log.error(errorMsg);
            throw new RuntimeException(errorMsg);
          }

          if (ssoValid) {

            log.debug("Saml userdata loaded, calling authUserSSO");

            String user[] = Getter.authUserSSO(ApplicationRoot, null, userName, ssoName, userRole);

            if (user != null && !user[0].isEmpty()) {

              // Kill Session and Create a new one with user logged in
              log.debug("Creating a new authenticated SSO session");
              ses.invalidate();
              ses = request.getSession(true);
              ses.setAttribute("userStamp", user[0]);
              ses.setAttribute("userName", user[1]);
              ses.setAttribute("userRole", user[2]);
              ses.setAttribute("lang", language);
              ses.setAttribute("userClass", user[4]);
              ses.setAttribute("attributes", attributes);
              ses.setAttribute("nameId", nameId);
              ses.setAttribute("nameIdFormat", nameIdFormat);
              ses.setAttribute("sessionIndex", sessionIndex);
              ses.setAttribute("nameidNameQualifier", nameidNameQualifier);
              ses.setAttribute("nameidSPNameQualifier", nameidSPNameQualifier);

              if ("true".equalsIgnoreCase(user[5])) {
                log.debug("Temporary Username Detected, user will be prompted to change");
                ses.setAttribute("ChangeUsername", "true");
              }

              log.debug("Setting CSRF cookie");
              CsrfToken.issue(request, response, ses);

              mustRedirect = true;

              // Removing user from kick list. If they were on it before, their suspension
              // must have ended if their authentication Succeeded
              UserKicker.removeFromKicklist(user[1]);
            }

            if (mustRedirect) {
              response.sendRedirect("../index.jsp");
            } else {
              ssoValid = false;
            }
          }

          if (!ssoValid) {
            log.debug("Could not authenticate");

            errorMessage += "SSO login failed.";
            ses.setAttribute("loginFailed", errorMessage);
            response.sendRedirect("../login.jsp");
          }
        }
      }
    }

    log.debug("**** End servlets.ACS ***");
  }

  /** Redirects user to index.jsp */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.sendRedirect("../index.jsp");
  }

  static String firstAttribute(Map<String, List<String>> attributes, String key) {
    List<String> values = attributeValues(attributes, key);
    if (values.isEmpty() || values.get(0) == null || values.get(0).isEmpty()) {
      return null;
    }
    return values.get(0);
  }

  private static List<String> attributeValues(Map<String, List<String>> attributes, String key) {
    if (attributes == null || key == null) {
      return Collections.emptyList();
    }
    List<String> values = attributes.get(key);
    return values == null ? Collections.emptyList() : values;
  }

  private static List<String> configuredAffiliations(String value) {
    if (value == null || value.trim().isEmpty()) {
      return Collections.emptyList();
    }
    return Arrays.asList(value.split(",[ ]*"));
  }
}
