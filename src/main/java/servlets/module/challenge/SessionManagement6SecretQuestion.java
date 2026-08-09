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
import java.util.concurrent.ConcurrentHashMap;
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

  // The secret answer is a single low entropy factor that is stored in the clear, so the number
  // of guesses one session may make against it is capped

  private static final int MAX_ANSWER_ATTEMPTS = 3;

  /**
   * Counts the answers that have been guessed wrong against each account. The count is held against
   * the account under attack rather than against the caller's session, because a session is under
   * the attacker's control: dropping the cookie and signing in again resets a session keyed
   * counter, and the whole answer space here is a handful of flowers. Keying it to the account is
   * what actually throttles the guessing.
   */
  private static final ConcurrentHashMap<String, Integer> failedAnswers = new ConcurrentHashMap<>();

  // A cap on the number of distinct accounts tracked, so that guesses against addresses that do
  // not exist cannot grow the map without bound
  private static final int MAX_TRACKED_ACCOUNTS = 10000;

  /**
   * Returns how many answers have already been guessed wrong against an account.
   *
   * @param account The address of the account being answered for
   * @return The number of wrong answers recorded against that account
   */
  private static int wrongAnswers(String account) {
    Integer wrong = failedAnswers.get(account);
    return wrong == null ? 0 : wrong;
  }

  /**
   * Records a wrong answer against an account.
   *
   * @param account The address of the account being answered for
   */
  private static void recordWrongAnswer(String account) {
    if (failedAnswers.size() >= MAX_TRACKED_ACCOUNTS && !failedAnswers.containsKey(account)) {
      failedAnswers.clear();
    }
    failedAnswers.merge(account, 1, Integer::sum);
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

        String ApplicationRoot = getServletContext().getRealPath("");
        Connection conn = null;
        try {
          if (Validate.isValidEmailAddress(subEmail)
              && subAns.length() > 5
              && wrongAnswers(subEmail) < MAX_ANSWER_ATTEMPTS) {
            conn = Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalSix");
            log.debug("Checking Secret Answer");
            PreparedStatement callstmt =
                conn.prepareStatement(
                    "SELECT userName FROM users WHERE userAddress = ? AND secretAnswer = ?");
            callstmt.setString(1, subEmail);
            callstmt.setString(2, subAns);
            log.debug("Running secret Answer Check");
            ResultSet rs = callstmt.executeQuery();
            log.debug("Answer checked, account recovery is never granted on an answer alone");
            // The secret answers are held in the clear beside the accounts they protect, so a
            // matching answer is not proof of ownership and never recovers the account. The
            // response is identical either way so it cannot be used as an oracle.
            rs.close();
            recordWrongAnswer(subEmail);
            htmlOutput =
                new String(
                    "<h2 class='title'>"
                        + bundle.getString("question.badAnswer")
                        + "</h2><p>"
                        + bundle.getString("question.whoAreYou"));
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
   * A user submits an email address to get that user's Secret Question
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
            Connection conn = null;
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
                conn =
                    Database.getChallengeConnection(
                        ApplicationRoot, "BrokenAuthAndSessMangChalSix");
                log.debug("Getting Secret Question");
                PreparedStatement callstmt =
                    conn.prepareStatement("SELECT secretQuestion FROM users WHERE userAddress = ?");
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
              log.error(levelName + " SQL Error: " + e.toString());
              htmlOutput = bundle.getString("question.noQuestion");
            } finally {
              Database.closeConnection(conn);
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
