package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import dbProcs.GetterIT;
import dbProcs.Setter;
import java.io.IOException;
import java.sql.SQLException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import testUtils.TestProperties;

public class PoorValidation2IT {

  private static String applicationRoot = new String();
  private static String USERNAME = "lessonTester";
  private static String LANG = "en_GB";

  private static final Logger log = LogManager.getLogger(PoorValidation2IT.class);

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  /** Creates DB or Restores DB to Factory Defaults before running tests */
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

    // Open All modules
    if (!Setter.openAllModules(applicationRoot, false)) {
      fail("Could not Mark All Modules As Open");
    }
  }

  private String submitOrder(
      String pineappleAmount, String orangeAmount, String appleAmount, String bananaAmount)
      throws Exception {
    String servletClassName = "PoorValidation2";
    log.debug("Creating " + servletClassName + " Servlet Instance");
    PoorValidation2 servlet = new PoorValidation2();
    servlet.init(new MockServletConfig(servletClassName));

    request.addParameter("pineappleAmount", pineappleAmount);
    request.addParameter("orangeAmount", orangeAmount);
    request.addParameter("appleAmount", appleAmount);
    request.addParameter("bananaAmount", bananaAmount);

    log.debug("Running doPost");
    servlet.doPost(request, response);

    return response.getContentAsString();
  }

  private void signIn() throws Exception {
    GetterIT.verifyTestUser(applicationRoot, USERNAME, USERNAME);
    log.debug("Signing in as " + USERNAME + " Through LoginServlet");
    TestProperties.loginDoPost(log, request, response, USERNAME, USERNAME, null, LANG);
    if (response.getCookie("token") == null) {
      fail("No CSRF Token Was Returned from Login Servlet");
    }
    request.setCookies(response.getCookies());
  }

  /**
   * Exploit attempt: previously, a huge positive orangeAmount overflowed the int-based cost
   * arithmetic (orangeAmount * 3000) around to a negative number, driving finalCost below zero
   * and unlocking the free-oranges response without a legitimate zero/low-cost order. With the
   * fix (amount clamped to a max + long arithmetic) this must no longer succeed.
   */
  @Test
  public void testIntegerOverflowExploitFails() throws Exception {
    signIn();
    String servletResponse = submitOrder("0", "1000000", "0", "0");
    assertFalse(
        servletResponse.contains("Oranges were free"),
        "Integer-overflow exploit unexpectedly produced the free-oranges response: "
            + servletResponse);
  }

  /** A second, even larger overflow attempt across multiple fields must also fail. */
  @Test
  public void testLargeMultiFieldOverflowExploitFails() throws Exception {
    signIn();
    String servletResponse = submitOrder("2000000000", "2000000000", "2000000000", "2000000000");
    assertFalse(
        servletResponse.contains("Oranges were free"),
        "Multi-field overflow exploit unexpectedly produced the free-oranges response: "
            + servletResponse);
  }

  /** Legitimate small order (one of each item) must still complete normally with the right total. */
  @Test
  public void testLegitimateOrderStillWorks() throws Exception {
    signIn();
    String servletResponse = submitOrder("1", "1", "1", "1");
    assertTrue(
        servletResponse.contains("3090"),
        "Legitimate order did not compute the expected total: " + servletResponse);
  }
}
