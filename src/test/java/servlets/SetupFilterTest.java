package servlets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

class SetupFilterTest {

  @Test
  void setupGate_allowsOnlyExactSetupRoutesAndRequiredAssets() {
    assertTrue(isAllowed("/shepherd/setup", "/shepherd"));
    assertTrue(isAllowed("/shepherd/setup.jsp", "/shepherd"));
    assertTrue(isAllowed("/shepherd/css/theCss.css", "/shepherd"));
    assertTrue(isAllowed("/shepherd/js/jquery.js", "/shepherd"));

    assertFalse(isAllowed("/shepherd/notsetup", "/shepherd"));
    assertFalse(isAllowed("/shepherd/admin/setup-users", "/shepherd"));
    assertFalse(isAllowed("/shepherd/login", "/shepherd"));
    assertFalse(isAllowed(null, "/shepherd"));
  }

  private static boolean isAllowed(String requestUri, String contextPath) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURI()).thenReturn(requestUri);
    when(request.getContextPath()).thenReturn(contextPath);
    return SetupFilter.isSetupResource(request);
  }
}
