package servlets.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
import utils.ScoreboardStatus;

public class ScoreboardIT {

  private static final Logger log = LogManager.getLogger(ScoreboardIT.class);
  private static final String APPLICATION_ROOT = "";
  private static final String LANGUAGE = "en_GB";
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
  public void setUp() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    ScoreboardStatus.setScoreboardOpen();
  }

  private void getScoreboard() throws ServletException, IOException {
    Scoreboard servlet = new Scoreboard();
    servlet.init(new MockServletConfig("Scoreboard"));
    servlet.doGet(request, response);
  }

  @Test
  public void testAnonymousUserCannotAccessOpenScoreboard() throws ServletException, IOException {
    getScoreboard();

    assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
  }

  @Test
  public void testAuthenticatedUserCanAccessOpenScoreboard() throws Exception {
    String userName = "apiScoreboardUser";
    TestProperties.verifyTestUser(log, APPLICATION_ROOT, userName, userName);
    TestProperties.loginDoPost(log, request, response, userName, userName, null, LANGUAGE);
    response = new MockHttpServletResponse();

    getScoreboard();

    assertEquals(HttpServletResponse.SC_OK, response.getStatus());
    assertEquals("true", response.getContentAsString());
  }

  @Test
  public void testAnonymousUserCanAccessPublicScoreboard() throws ServletException, IOException {
    ScoreboardStatus.setScoreboardPublic();

    getScoreboard();

    assertEquals(HttpServletResponse.SC_OK, response.getStatus());
    assertEquals("true", response.getContentAsString());
  }
}
