package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.SessionManagementRecoveryGuard;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge 7 - Security Question Does not return result key <br>
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
public class SessionManagement7SecretQuestion extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement7SecretQuestion.class);
  private static String levelName = "Session Management Challenge 7 (Secret Question)";
  private static String levelHash =
      "269d55bc0e0ff635dcaeec8533085e5eae5d25e8646dcd4b05009353c9cf9c80";
  // To catch most requests before calling the DB, the in comming Answers must be one of the
  // following flowers
  private static String possibleAnswers[] = {
    new String("Jade Vine"),
    new String("Corpse Flower"),
    new String("Gibraltar Campion"),
    new String("Franklin Tree"),
    new String("Middlemist Red"),
    new String("Chocolate Cosmos"),
    new String("Ghost Orchid")
  };

  /** Namespace for this challenge's recovery state inside the player's HttpSession. */
  private static final String CHALLENGE_KEY = "sessionManagement7";

  /**
   * Recovery response. Identical for every outcome so that the endpoint is not an oracle for
   * whether an account exists or whether a secret answer was correct. Hard coded English, in the
   * same way as the hard coded question string below, because the i18n bundle for this challenge
   * has no key for this message.
   */
  private static final String RECOVERY_RESPONSE =
      "If those details match an account, password reset instructions have been sent to the email"
          + " address on file. Account recovery can never sign you in.";

  /**
   * A user submits an email address and secret answer. The answer is checked against the DB with a
   * bound parameter, but a correct answer never authenticates the caller and never returns a result
   * key - a knowledge based answer is not an authenticator. The submission must carry the single
   * use recovery token this session was issued, and attempts are capped per session.
   *
   * @param subEmail Sub schema user email to search DB with
   * @param subAnswer Sub schema user secret answer to check against the DB
   * @param recoveryToken Single use recovery token issued by the secret question request
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
            "i18n.servlets.challenges.sessionManagement.sessionManagement7", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      String htmlOutput = new String();
      log.debug(levelName + " Servlet accessed");
      try {
        log.debug("Getting Challenge Parameters");
        String subAns = Validate.validateParameter(request.getParameter("subAnswer"), 35);
        String subEmail = Validate.validateParameter(request.getParameter("subEmail"), 60);
        String subToken = Validate.validateParameter(request.getParameter("recoveryToken"), 128);

        String ApplicationRoot = getServletContext().getRealPath("");

        if (subEmail.isEmpty() || !Validate.isValidEmailAddress(subEmail) || subAns.length() < 5) {
          log.debug("Invalid data submitted");
          htmlOutput = new String("<b>" + bundle.getString("question.invalidData") + ": </b>");
          if (subAns.length() < 5) {
            htmlOutput += bundle.getString("question.invalidAns");
          } else {
            htmlOutput += bundle.getString("question.invalidEmail");
          }
        } else {
          // Uniform response: recovery never confirms an account and never authenticates.
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.welcome")
                  + "</h2><p>"
                  + RECOVERY_RESPONSE
                  + "</p>";
          if (SessionManagementRecoveryGuard.isLockedOut(ses, CHALLENGE_KEY)) {
            log.error(
                "Recovery attempt limit reached by " + ses.getAttribute("userName").toString());
          } else {
            SessionManagementRecoveryGuard.recordAttempt(ses, CHALLENGE_KEY);
            if (!SessionManagementRecoveryGuard.isValidToken(
                ses, CHALLENGE_KEY, subToken, subEmail)) {
              log.error("Secret answer submitted without a valid session bound recovery token");
            } else if (!validAnswer(subAns)) {
              log.debug("Invalid answer submitted for any user, skipping rest of function");
            } else {
              try (Connection conn =
                      Database.getChallengeConnection(
                          ApplicationRoot, "BrokenAuthAndSessMangChalFlowers");
                  PreparedStatement callstmt =
                      conn.prepareStatement(
                          "SELECT userName FROM users WHERE userAddress = ? AND secretAnswer = ?")) {
                callstmt.setString(1, subEmail);
                callstmt.setString(2, subAns);
                log.debug("Running secret Answer Check");
                try (ResultSet rs = callstmt.executeQuery()) {
                  if (rs.next()) {
                    // A knowledge based answer is not an authenticator. The single use token is
                    // burned and a reset mail would be issued out of band. No session is granted
                    // and no result key is returned from the recovery path.
                    log.debug("Correct answer submitted, reset mail would be issued");
                    SessionManagementRecoveryGuard.consumeToken(ses, CHALLENGE_KEY);
                  } else {
                    log.debug("Bad Answer Submitted");
                  }
                }
              } catch (SQLException e) {
                log.error(levelName + " SQL Error: " + e.toString());
              }
            }
          }
        }
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
   * A user submits an email address to get that user's Secret Question. A single use recovery token
   * is issued alongside the question so that an answer can only be submitted by the session that
   * asked for the question.
   *
   * @param subEmail Sub schema user email to search DB with
   */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String levelName = "Session Management Challenge 7 (Get Question)";
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement7", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      log.debug(levelName + " Servlet accessed");
      try {
        log.debug("Getting Cookies");
        Cookie userCookies[] = request.getCookies();
        Cookie theCookie = null;
        if (userCookies != null) {
          for (int i = 0; i < userCookies.length; i++) {
            if (userCookies[i].getName().compareTo("ac") == 0) {
              theCookie = userCookies[i];
              break; // End Loop, because we found the token
            }
          }
        }
        if (theCookie != null) {
          log.debug("Cookie value: " + theCookie.getValue());
          byte[] decodedCookieBytes = Base64.decodeBase64(theCookie.getValue());
          String decodedCookie = new String(decodedCookieBytes, "UTF-8");
          log.debug("Decoded Cookie: " + decodedCookie);
          if (decodedCookie.equals("doNotReturnAnswers")) // Untampered Cookie
          {
            String subEmail = Validate.validateParameter(request.getParameter("subEmail"), 60);
            // Question not translated as DB will only mark English answers as correct
            htmlOutput = new String("What is your favourite flower?");
            if (!subEmail.isEmpty() && Validate.isValidEmailAddress(subEmail)) {
              String recoveryToken =
                  SessionManagementRecoveryGuard.issueToken(ses, CHALLENGE_KEY, subEmail);
              htmlOutput +=
                  "<input type='hidden' id='recoveryToken' value='"
                      + Encode.forHtmlAttribute(recoveryToken)
                      + "'/>";
            }
          } else {
            log.debug("Tampered cookie detected");
            htmlOutput = bundle.getString("response.configError");
          }
        } else {
          log.debug("Tampered cookie detected");
          htmlOutput = bundle.getString("response.configError");
        }
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

  private static boolean validAnswer(String submittedAns) {
    for (int i = 0; i < possibleAnswers.length; i++) {
      if (possibleAnswers[i].equalsIgnoreCase(submittedAns)) {
        return true;
      }
    }
    return false;
  }
}
