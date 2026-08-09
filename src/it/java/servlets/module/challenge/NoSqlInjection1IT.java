package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.fail;

import dbProcs.GetterIT;
import dbProcs.Setter;
import java.io.IOException;
import java.sql.SQLException;
import javax.servlet.ServletException;
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

public class NoSqlInjection1IT extends Mockito {

  private static String applicationRoot = new String();
  private static String USERNAME = "lessonTester";
  private static String LANG = "en_GB";
  private static String NOSQL_ATTACK = "';return(true);var a='a";
  // Jimmy's real gamer _id: this is the exact literal value the challenge page's own hidden
  // #theGamerName field submits (see the challenge JSP), so it is the genuine, legitimate
  // request this feature exists to serve.
  private static String LEGITIMATE_GAMER_ID =
      "b43c05a8166b5bbc5e2baebbbc84a71f83fd7cac01dd5d23bb6e003a95d60b7c";

  private static final Logger log = LogManager.getLogger(NoSqlInjection1IT.class);

  @Mock private MockHttpServletRequest request;

  @Mock private MockHttpServletResponse response;

  /** Creates DB or Restores DB to Factory Defaults before running tests */
  @BeforeAll
  public static void resetDatabase() throws IOException, SQLException {
    TestProperties.setTestPropertiesFileDirectory(log);

    TestProperties.createMysqlResource();
    TestProperties.createMongoResource();

    TestProperties.ensureSchemaReady(log);
    TestProperties.reseedTestData();
  }

  @BeforeEach
  public void setup() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();

    // Open All modules
    if (!Setter.openAllModules(applicationRoot, false)) {
      fail("Could not Mark All Modules As Open");
    }
  }

  public String moduleDoPost(String theSubmission, String csrfToken, int expectedResponseCode)
      throws ServletException, IOException {

    String servletClassName = "NoSqlInjection1";
    log.debug("Creating " + servletClassName + " Servlet Instance");
    NoSqlInjection1 servlet = new NoSqlInjection1();
    servlet.init(new MockServletConfig(servletClassName));

    // Setup Servlet Parameters and Attributes
    log.debug("Setting Up Params and Atrributes");
    request.addParameter("theGamerName", theSubmission);
    // Adding Correct CSRF Token (Token Submitted)
    request.addParameter("csrfToken", csrfToken);

    if (request == null) {
      log.debug("Request is null");
    }
    if (response == null) {
      log.debug("Request is null");
    }

    log.debug("Running doPost");
    servlet.doPost(request, response);

    if (response.getStatus() != expectedResponseCode) {
      fail(
          servletClassName
              + " Servlet Returned "
              + response.getStatus()
              + " Code. "
              + expectedResponseCode
              + " Expected");
    } else {
      log.debug("302 OK Detected");
      log.debug(
          servletClassName
              + " Successful, returning location retrieved: "
              + response.getContentAsString());
      return (response.getContentAsString());
    }

    return null;
  }

  @Test
  public void testLegitimateLookupStillWorks() throws Exception {

    GetterIT.verifyTestUser(applicationRoot, USERNAME, USERNAME);
    log.debug("Signing in as " + USERNAME + " Through LoginServlet");
    TestProperties.loginDoPost(log, request, response, USERNAME, USERNAME, null, LANG);
    log.debug("Login Servlet Complete, Getting CSRF Token");
    if (response.getCookie("token") == null) {
      fail("No CSRF Tokena Was Returned from Login Servlet");
    }
    String csrfToken = response.getCookie("token").getValue();
    if (csrfToken.isEmpty()) {
      String message = new String("No CSRF token returned from Login Servlet");
      log.fatal(message);
      fail(message);
    } else {
      request.setCookies(response.getCookies());
      // A legitimate lookup by the exact, literal gamer id must still return that gamer's row.
      String servletResponse = moduleDoPost(LEGITIMATE_GAMER_ID, csrfToken, 302);
      if (servletResponse.contains("An error was detected")) {
        String message = new String("Legitimate lookup returned an error");
        log.fatal(message);
        fail(message);
      } else if (!servletResponse.contains("Jimmy</td><td>Baltimore</td>")) {
        String message =
            new String("Legitimate exact-id lookup did not return the expected gamer row");
        log.fatal(message);
        fail(message);
      }
    }
  }

  @Test
  public void testNoSqlInjectionAttackIsRejected() throws Exception {

    GetterIT.verifyTestUser(applicationRoot, USERNAME, USERNAME);
    log.debug("Signing in as " + USERNAME + " Through LoginServlet");
    TestProperties.loginDoPost(log, request, response, USERNAME, USERNAME, null, LANG);
    if (response.getCookie("token") == null) {
      fail("No CSRF Tokena Was Returned from Login Servlet");
    }
    String csrfToken = response.getCookie("token").getValue();
    if (csrfToken.isEmpty()) {
      String message = new String("No CSRF token returned from Login Servlet");
      log.fatal(message);
      fail(message);
    } else {
      request.setCookies(response.getCookies());
      // The classic "$where" JS-injection payload must no longer dump the whole gamer
      // collection: it is now compared as a plain literal string against _id, which never
      // matches any seeded document, so the response must fall back to the "no results" case.
      String servletResponse = moduleDoPost(NOSQL_ATTACK, csrfToken, 302);
      if (servletResponse.contains("Baltimore")) {
        String message = new String("NoSQL injection payload leaked gamer records");
        log.fatal(message);
        fail(message);
      }
    }
  }
}
