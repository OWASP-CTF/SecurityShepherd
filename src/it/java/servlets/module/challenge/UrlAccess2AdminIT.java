package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dbProcs.GetterIT;
import java.io.IOException;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import testUtils.TestProperties;

/**
 * Regression coverage for the "Failure to Restrict URL Access 2" challenge. The admin-only function
 * must reject any session that is not actually holding the admin role, even when the caller already
 * knows (or has guessed/reverse-engineered) the hidden request parameters the admin action expects.
 */
public class UrlAccess2AdminIT {

  private static final Logger log = LogManager.getLogger(UrlAccess2AdminIT.class);
  private static final String LANG = "en_GB";
  private static final String applicationRoot = "";

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @BeforeAll
  public static void resetDatabase() throws IOException, SQLException {
    TestProperties.setTestPropertiesFileDirectory(log);
    TestProperties.createMysqlResource();
    TestProperties.ensureSchemaReady(log);
    TestProperties.reseedTestData();
  }

  @BeforeEach
  public void setup() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
  }

  private UrlAccess2Admin newServletInstance() throws ServletException {
    UrlAccess2Admin servlet = new UrlAccess2Admin();
    servlet.init(new MockServletConfig("UrlAccess2Admin"));
    return servlet;
  }

  @Test
  public void nonAdminPlayerIsForbiddenFromAdminFunction() throws Exception {
    String userName = "urlAccess2Player";
    GetterIT.verifyTestUser(applicationRoot, userName, userName);
    TestProperties.loginDoPost(log, request, response, userName, userName, null, LANG);
    request.setCookies(response.getCookies());

    // Fresh response for the challenge call: the mock response object still carries the 302
    // status set by the login redirect above, and the servlet under test never calls
    // setStatus() on a success path (only sendError() on rejection), so reusing it would let a
    // stale 302 mask a missing access-control check.
    MockHttpServletResponse challengeResponse = new MockHttpServletResponse();
    request.addParameter("adminData", "youAreAnAdminOfAwesomenessWoopWoop");

    newServletInstance().doPost(request, challengeResponse);

    assertEquals(
        HttpServletResponse.SC_FORBIDDEN,
        challengeResponse.getStatus(),
        "A regular player must not be able to invoke the admin-only URL Access 2 function.");
  }

  @Test
  public void adminUserReceivesResultKey() throws Exception {
    String userName = "urlAccess2Admin";
    GetterIT.verifyTestAdmin(applicationRoot, userName, userName);
    TestProperties.loginDoPost(log, request, response, userName, userName, null, LANG);
    request.setCookies(response.getCookies());

    MockHttpServletResponse challengeResponse = new MockHttpServletResponse();
    request.addParameter("adminData", "youAreAnAdminOfAwesomenessWoopWoop");

    newServletInstance().doPost(request, challengeResponse);

    assertEquals(
        HttpServletResponse.SC_OK,
        challengeResponse.getStatus(),
        "A real admin must still be able to complete the legitimate admin function.");
    String body = challengeResponse.getContentAsString();
    assertTrue(
        body != null && !body.isEmpty() && !body.contains("failue"),
        "Admin response should contain the result key output, not the failure branch.");
  }
}
