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

  /** Session-scoped count of secret-answer attempts, and the cap on them. */
  private static final String ANSWER_ATTEMPTS = "sessionManagement7AnswerAttempts";

  private static final int MAX_ANSWER_ATTEMPTS = 5;
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

  /**
   * A user submits a username and answer, these values are checked against the DB to see if they
   * are valid
   *
   * @param subEmail Sub schema user email to search DB with
   * @param subAnswer Sub schema user secret answer to check against the DB
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

        Object ansObj = request.getParameter("subAnswer");
        String subAns = Validate.validateParameter(ansObj, 35);
        log.debug("subAnswer = " + subAns);
        Object emailObj = request.getParameter("subEmail");
        String subEmail = Validate.validateParameter(emailObj, 60);
        log.debug("subEmail = " + subEmail);
        // ASVS 2.4: the recovery answer comes from a small, guessable set, so the number of
        // attempts a session may make is capped. Without this the flow was brute-forceable.
        Integer attempts = (Integer) ses.getAttribute(ANSWER_ATTEMPTS);
        if (attempts == null) {
          attempts = Integer.valueOf(0);
        }
        if (attempts.intValue() >= MAX_ANSWER_ATTEMPTS) {
          log.debug("Secret answer attempt limit reached for this session");
          out.write("<b>" + bundle.getString("question.tooManyAttempts") + "</b>");
          return;
        }
        ses.setAttribute(ANSWER_ATTEMPTS, Integer.valueOf(attempts.intValue() + 1));
        if (validAnswer(subAns)) {
          log.debug("Submitted answer is a possible valid answer");
          String ApplicationRoot = getServletContext().getRealPath("");
          try {
            if (Validate.isValidEmailAddress(subEmail) && subAns.length() > 5) {
              Connection conn =
                  Database.getChallengeConnection(
                      ApplicationRoot, "BrokenAuthAndSessMangChalFlowers");
              log.debug("Checking Secret Answer");
              PreparedStatement callstmt =
                  conn.prepareStatement(
                      "SELECT userName FROM users WHERE userAddress = ? AND secretAnswer = ?");
              callstmt.setString(1, subEmail);
              callstmt.setString(2, subAns);
              log.debug("Running secret Answer Check");
              ResultSet rs = callstmt.executeQuery();
              if (rs.next()) {

                // A secret answer is a weak, guessable factor: knowing it is not proof that the

                // account belongs to the requester, so it does not by itself grant access. The

                // reset is sent to the address on file instead (ASVS 6.4).

                log.debug("Recovery answer accepted; reset sent out of band");

                htmlOutput =
                    new String(
                        "<h2 class='title'>" + bundle.getString("question.recoverySent") + "</h2>");

              } else {
                log.debug("Bad Answer Submitted");
                htmlOutput =
                    new String(
                        "<h2 class='title'>"
                            + bundle.getString("question.badAnswer")
                            + "</h2><p>"
                            + bundle.getString("question.whoAreYou")
                            + "</p>");
              }
              Database.closeConnection(conn);
            } else {
              log.debug("Invalid data submitted");
              htmlOutput = new String("<b>" + bundle.getString("question.invalidData") + ": </b>");
              if (subAns.length() < 5) {
                htmlOutput += bundle.getString("question.invalidAns");
              } else {
                htmlOutput += bundle.getString("question.invalidEmail");
              }
            }
          } catch (SQLException e) {
            log.error(levelName + " SQL Error: " + e.toString());
          }
        } else {
          log.debug("Invalid answer submitted for any user, skipping rest of function");
          htmlOutput =
              new String(
                  "<h2 class='title'>"
                      + bundle.getString("question.badAnswer")
                      + "</h2><p>"
                      + bundle.getString("question.whoAreYou")
                      + "</p>");
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
   * A user submits an email address to get that user's Secret QUestion. This is vulnerable to SQL
   * injection
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
        int i = 0;
        Cookie theCookie = null;
        for (i = 0; i < userCookies.length; i++) {
          if (userCookies[i].getName().compareTo("ac") == 0) {
            theCookie = userCookies[i];
            break; // End Loop, because we found the token
          }
        }
        if (theCookie != null) {
          log.debug("Cookie value: " + theCookie.getValue());
          log.debug("Cookie value: " + theCookie.getValue());
          byte[] decodedCookieBytes = Base64.decodeBase64(theCookie.getValue());
          String decodedCookie = new String(decodedCookieBytes, "UTF-8");
          log.debug("Decoded Cookie: " + decodedCookie);
          if (decodedCookie.equals("doNotReturnAnswers")) // Untampered Cookie
          {
            // Question not translated as DB will only mark English answers as correct
            htmlOutput = new String("What is your favourite flower?");
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
