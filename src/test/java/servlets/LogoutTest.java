package servlets;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

class LogoutTest {

  @Test
  void get_isRejectedBecauseLogoutChangesState() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);

    new Logout().doGet(request, response);

    verify(response).setHeader("Allow", "POST");
    verify(response).sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
  }
}
