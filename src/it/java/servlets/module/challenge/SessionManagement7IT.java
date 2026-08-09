package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dbProcs.Database;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import testUtils.TestProperties;

/**
 * Regression coverage for Session Management Challenge 7: the login handler used to leak a
 * submitted user name's registered email address on a wrong password (a user-enumeration/PII
 * oracle), and the account-recovery secret question handed out the level's result key to anyone who
 * could match a "favourite flower" style answer - treating a shared, guessable fact as equivalent
 * to a real login. Both issues fed each other - the login oracle handed an attacker a target email,
 * then the secret question let them take the account over with it.
 */
public class SessionManagement7IT extends Mockito {

  private static final Logger log = LogManager.getLogger(SessionManagement7IT.class);
  private static final String applicationRoot = "";
  private static final String LANG = "en_GB";

  // Seeded rows from BrokenAuthAndSessMangChalSeven (moduleSchemas.sql): known user names, their
  // real registered email addresses, and (for the second servlet) their real secret answers.
  private static final String KNOWN_USER = "sean";
  private static final String KNOWN_USER_EMAIL = "zoidberg24@shepherd.com";
  private static final String OTHER_USER_EMAIL = "zoidberg23@shepherd.com"; // belongs to "manager"
  private static final String WRONG_BUT_VALID_ANSWER = "Ghost Orchid"; // a real flower, wrong here

  @Mock private MockHttpServletRequest request;

  @Mock private MockHttpServletResponse response;

  @BeforeAll
  public static void resetDatabase() throws IOException, SQLException {
    TestProperties.setTestPropertiesFileDirectory(log);
    TestProperties.createMysqlResource();
    TestProperties.ensureSchemaReady(log);
    TestProperties.reseedTestData();

    // moduleSchemas.sql grants the per-challenge DB user (e.g. randomFlower) access scoped to
    // 'localhost' only, which matches a real Tomcat<->MariaDB connection on the docker-compose
    // network but not this test JVM connecting over a locally-published TCP port. Widen it to '%'
    // purely for this test run so the servlet's real Database.getChallengeConnection() codepath
    // (connecting as randomFlower, exactly as production does) can be exercised end-to-end.
    try (Connection root = Database.getDatabaseConnection(null, true);
        Statement stmt = root.createStatement()) {
      stmt.execute(
          "GRANT ALL PRIVILEGES ON `BrokenAuthAndSessMangChalSeven`.* TO 'randomFlower'@'%'"
              + " IDENTIFIED BY 'c21-le_6oT'");
      stmt.execute("FLUSH PRIVILEGES");
    }
  }

  @BeforeEach
  public void setup() throws SQLException {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
  }

  private void loginAsFreshPlayer(String userName) throws SQLException {
    TestProperties.verifyTestUser(log, applicationRoot, userName, userName);
    TestProperties.loginDoPost(log, request, response, userName, userName, null, LANG);
  }

  private String loginServletDoPost(String subName, String subPassword)
      throws ServletException, IOException {
    SessionManagement7 servlet = new SessionManagement7();
    servlet.init(new MockServletConfig("SessionManagement7"));

    Cookie ackCookie =
        new Cookie("ac", Base64.encodeBase64String("doNotReturnAnswers".getBytes("UTF-8")));
    request.setCookies(ackCookie);
    // setParameter (not addParameter) so repeated calls on the same reused request overwrite
    // the prior value instead of accumulating it as an extra value behind the first one.
    request.setParameter("subName", subName);
    request.setParameter("subPassword", subPassword);

    response = new MockHttpServletResponse();
    servlet.doPost(request, response);
    return response.getContentAsString();
  }

  private String secretQuestionServletDoPost(String subEmail, String subAnswer)
      throws ServletException, IOException {
    SessionManagement7SecretQuestion servlet = new SessionManagement7SecretQuestion();
    servlet.init(new MockServletConfig("SessionManagement7SecretQuestion"));

    request.setParameter("subEmail", subEmail);
    request.setParameter("subAnswer", subAnswer);

    response = new MockHttpServletResponse();
    servlet.doPost(request, response);
    return response.getContentAsString();
  }

  /**
   * Exploit for the login oracle: submitting a real user name with a wrong password used to
   * disclose that user's registered email address; a made-up user name responded differently. Both
   * must now be identical, generic responses with no email address anywhere in them.
   */
  @Test
  public void testLoginNoLongerLeaksEmailForKnownOrUnknownUser()
      throws SQLException, ServletException, IOException, UnsupportedEncodingException {
    loginAsFreshPlayer("sm7LoginOracleTester");

    String knownUserResponse = loginServletDoPost(KNOWN_USER, "definitelyWrongPassword");
    String unknownUserResponse =
        loginServletDoPost("thisUserNameDoesNotExistAtAll42", "definitelyWrongPassword");
    String administratorResponse = loginServletDoPost("administrator", "definitelyWrongPassword");

    assertFalse(
        knownUserResponse.contains(KNOWN_USER_EMAIL),
        "Wrong password for a real user name must not disclose that user's email address");
    assertFalse(
        administratorResponse.contains("buzzthebald@shepherd.com"),
        "Wrong password for 'administrator' must not disclose the administrator's email address");
    assertTrue(
        knownUserResponse.equals(unknownUserResponse)
            && unknownUserResponse.equals(administratorResponse),
        "A real user name and a made-up one must now produce an identical response, closing the"
            + " user-enumeration oracle");
  }

  /**
   * Exploit for the secret-question shortcut: the security question only ever has one of 7 possible
   * flowers as the real answer, so anyone who already has a target's email address (or simply
   * guesses right) used to be handed the challenge's result key directly - no real sign-in
   * required. A knowledge-based answer must no longer be treated as equivalent to authenticating,
   * so even the genuinely correct answer must not return the key.
   */
  @Test
  public void testSecretQuestionNoLongerGrantsKeyOnCorrectAnswer()
      throws SQLException, ServletException, IOException {
    loginAsFreshPlayer("sm7SecretQTester");

    String correctAnswerResponse =
        secretQuestionServletDoPost(OTHER_USER_EMAIL, "Jade Vine"); // manager's real answer

    assertFalse(
        correctAnswerResponse.contains("result key"),
        "A correct secret-answer match must no longer disclose the level's result key: "
            + correctAnswerResponse);
    assertTrue(
        correctAnswerResponse.contains("Welcome"),
        "The endpoint should still acknowledge a matched answer, just without the key: "
            + correctAnswerResponse);
  }

  /**
   * The secret-question endpoint itself must keep functioning normally (no errors, still
   * distinguishes a matching answer from a non-matching one) - only the key disclosure was removed,
   * not the whole feature.
   */
  @Test
  public void testSecretQuestionStillDistinguishesRightFromWrongAnswer()
      throws SQLException, ServletException, IOException {
    loginAsFreshPlayer("sm7SecretQWrongAnswerTester");

    String wrongAnswerResponse =
        secretQuestionServletDoPost(OTHER_USER_EMAIL, WRONG_BUT_VALID_ANSWER);
    String correctAnswerResponse = secretQuestionServletDoPost(OTHER_USER_EMAIL, "Jade Vine");

    assertFalse(
        wrongAnswerResponse.contains("An Error Occurred"),
        "The endpoint must not error out on a wrong-but-plausible answer: " + wrongAnswerResponse);
    assertFalse(
        wrongAnswerResponse.equals(correctAnswerResponse),
        "A matching answer must still be distinguishable from a non-matching one, even though"
            + " neither discloses the key");
  }
}
