package servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dbProcs.Setter;
import java.io.IOException;
import java.sql.SQLException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import testUtils.TestProperties;

public class ModuleStatusFilterIT {

  private static final Logger log = LogManager.getLogger(ModuleStatusFilterIT.class);
  private static final String APPLICATION_ROOT = "";
  private ModuleStatusFilter filter;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private RecordingFilterChain chain;

  @BeforeAll
  public static void resetDatabase() throws IOException, SQLException {
    TestProperties.setTestPropertiesFileDirectory(log);
    TestProperties.createMysqlResource();
    TestProperties.ensureSchemaReady(log);
    TestProperties.reseedTestData();
  }

  @BeforeEach
  public void setUp() throws ServletException {
    Setter.openAllModules(APPLICATION_ROOT, false);
    filter = new ModuleStatusFilter();
    filter.init(new MockFilterConfig("ModuleStatusFilter"));
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    chain = new RecordingFilterChain();
  }

  @Test
  public void testClosedUrlAccessTwoTargetIsRejected() throws Exception {
    Setter.setModuleStatusClosed(APPLICATION_ROOT, "c7ac1e05faa2d4b1016cfcc726e0689419662784");
    request.setServletPath(
        "/challenges/278fa30ee727b74b9a2522a5ca3bf993087de5a0ac72adff216002abf79146fahghghmin");

    filter.doFilter(request, response, chain);

    assertEquals(403, response.getStatus());
    assertFalse(chain.wasCalled);
  }

  @Test
  public void testClosedUrlAccessThreeUserListIsRejected() throws Exception {
    Setter.setModuleStatusClosed(APPLICATION_ROOT, "adc845f9624716eefabcc90d172bab4096fa2ac4");
    request.setServletPath(
        "/challenges/e40333fc2c40b8e0169e433366350f55c77b82878329570efa894838980de5b4UserList");

    filter.doFilter(request, response, chain);

    assertEquals(403, response.getStatus());
    assertFalse(chain.wasCalled);
  }

  @Test
  public void testOpenAndUnknownRoutesContinue() throws Exception {
    request.setServletPath(
        "/challenges/278fa30ee727b74b9a2522a5ca3bf993087de5a0ac72adff216002abf79146fa");

    filter.doFilter(request, response, chain);

    assertTrue(chain.wasCalled);

    request.setServletPath("/challenges/static-resource.js");
    chain = new RecordingFilterChain();
    filter.doFilter(request, response, chain);

    assertTrue(chain.wasCalled);
  }

  private static class RecordingFilterChain implements FilterChain {

    private boolean wasCalled;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response)
        throws IOException, ServletException {
      wasCalled = true;
    }
  }
}
