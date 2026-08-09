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
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Six - Security Question Does not return result key <br>
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
public class SessionManagement6SecretQuestion extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement6SecretQuestion.class);
  private static String levelName = "Session Management Challenge Six (Secret Question)";
  private static String levelHash =
      "b5e1020e3742cf2c0880d4098146c4dde25ebd8ceab51807bad88ff47c316ece";

  /**
   * A secret question draws its answer from a small, shared, guessable pool - this challenge's is
   * seven flowers - so an unlimited number of tries turns the question into a lookup table. The
   * session is given a fixed allowance and every submission spends one of it, whether the answer
   * was plausible or not.
   */
  private static final int MAX_ANSWER_ATTEMPTS = 5;

  private static final String ANSWER_ATTEMPTS_ATTRIBUTE = "sessionManagement6SecretAnswerAttempts";

  private static boolean answerAllowanceSpent(HttpSession ses) {
    Object counted = ses.getAttribute(ANSWER_ATTEMPTS_ATTRIBUTE);
    int attempts = (counted instanceof Integer) ? ((Integer) counted).intValue() : 0;
    if (attempts >= MAX_ANSWER_ATTEMPTS) {
      return true;
    }
    ses.setAttribute(ANSWER_ATTEMPTS_ATTRIBUTE, Integer.valueOf(attempts + 1));
    return false;
  }

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
            "i18n.servlets.challenges.sessionManagement.sessionManagement6", locale);

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
        Object emailObj = request.getParameter("subEmail");
        String subEmail = Validate.validateParameter(emailObj, 60);
        log.debug("subEmail = " + subEmail);
        Object ansObj = request.getParameter("subAnswer");
        String subAns = Validate.validateParameter(ansObj, 128);
        log.debug("subAnswer = " + subAns);

        if (answerAllowanceSpent(ses)) {
          log.error("Refused a secret answer: this session has used its allowance of attempts");
          out.write(bundle.getString("question.tooManyAttempts"));
          return;
        }

        String ApplicationRoot = getServletContext().getRealPath("");
        Connection conn = null;
        try {
          if (Validate.isValidEmailAddress(subEmail) && subAns.length() > 5) {
            conn = Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalSix");
            log.debug("Checking Secret Answer");
            PreparedStatement callstmt =
                conn.prepareStatement(
                    "SELECT userName FROM users WHERE userAddress = ? AND secretAnswer = ?");
            callstmt.setString(1, subEmail);
            callstmt.setString(2, subAns);
            log.debug("Running secret Answer Check");
            ResultSet rs = callstmt.executeQuery();
            if (rs.next()) {
              // Answering the secret question confirms who the caller claims to be and nothing
              // more. It is a shared, guessable fact, not a credential, so it cannot stand in
              // for signing in to the account - and it certainly cannot earn the key that is
              // only given for holding the account's real authentication.
              // The reply confirms the answer and nothing else. Naming the account handed the
              // caller a list of who is worth attacking for every address they guessed at.
              log.debug("Correct Answer Submitted");
              htmlOutput =
                  "<h2 class='title'>"
                      + bundle.getString("response.welcome")
                      + "</h2><p>"
                      + bundle.getString("question.whoAreYou")
                      + "</p>";
            } else {
              log.debug("Bad Answer Submitted");
              htmlOutput =
                  new String(
                      "<h2 class='title'>"
                          + bundle.getString("question.badAnswer")
                          + "</h2><p>"
                          + bundle.getString("question.whoAreYou"));
            }
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
        } finally {
          // The close used to sit on the success path only, so a SQL error kept the connection.
          Database.closeConnection(conn);
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
    String levelName = "Session Management Challenge Six (Get Question)";
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement6", locale);

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
        // A request that carries no cookies at all hands back null here, not an empty array.
        // Walking it unguarded threw out of the check instead of failing it.
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
          byte[] decodedCookieBytes = Base64.decodeBase64(theCookie.getValue());
          String decodedCookie = new String(decodedCookieBytes, "UTF-8");
          log.debug("Decoded Cookie: " + decodedCookie);

          if (decodedCookie.equals("doNotReturnAnswers")) // Untampered Cookie
          {
            log.debug("Getting Parameter");
            Object emailObj = request.getParameter("subEmail");
            String subEmail = Validate.validateParameter(emailObj, 75);
            log.debug("subEmail = " + subEmail);

            String ApplicationRoot = getServletContext().getRealPath("");
            Connection questionConn = null;
            try {
              if (subEmail.length() < 10) {
                log.debug("Invalid data submitted");
                htmlOutput =
                    new String(
                        "<b>"
                            + bundle.getString("question.invalidData")
                            + ": </b>"
                            + bundle.getString("question.invalidEmail"));
              } else {
                questionConn =
                    Database.getChallengeConnection(
                        ApplicationRoot, "BrokenAuthAndSessMangChalSix");
                log.debug("Getting Secret Question");
                // The address is bound, not pasted into the statement. Concatenated here it let
                // the caller rewrite the lookup and read whatever the challenge user could
                // reach, rather than the one question they asked for.
                PreparedStatement callstmt =
                    questionConn.prepareStatement(
                        "SELECT secretQuestion FROM users WHERE userAddress = ?");
                callstmt.setString(1, subEmail);
                ResultSet rs = callstmt.executeQuery();
                if (rs.next()) {
                  log.debug("'Valid' User Detected");
                  log.debug("Encoding for output: " + rs.getString(1));
                  // rs.getString(1) contains the question for the user to answer. This question is
                  // asked in English as it must be answered in English to successfully pass the
                  // level
                  htmlOutput = new String(Encode.forHtml(rs.getString(1)));
                } else {
                  log.debug("No question found for user");
                  htmlOutput = bundle.getString("question.noQuestion");
                }
              }
            } catch (SQLException e) {
              // The database's own complaint stays in the log. Handed to the caller it names
              // tables, columns and the statement that failed, which is how a query gets rebuilt
              // until it returns something it should not.
              log.error(levelName + " SQL Error: " + e.toString());
              htmlOutput = new String(bundle.getString("question.noQuestion"));
            } finally {
              // The close used to sit on the success path only, so a SQL error kept the
              // connection out of the pool for good.
              Database.closeConnection(questionConn);
            }
          } else {
            log.debug("Tampered cookie detected");
            htmlOutput = new String(bundle.getString("response.configError"));
          }
        } else {
          log.debug("Tampered cookie detected");
          htmlOutput = new String(bundle.getString("response.configError"));
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
}
