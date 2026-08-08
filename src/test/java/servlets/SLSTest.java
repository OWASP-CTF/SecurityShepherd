package servlets;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

class SLSTest {

  @Test
  void get_isRoutedToTheSamlLogoutHandler() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);

    new SLS().doGet(request, response);

    verify(response).sendRedirect("../login.jsp");
  }

  @Test
  void post_isRoutedToTheSamlLogoutHandler() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);

    new SLS().doPost(request, response);

    verify(response).sendRedirect("../login.jsp");
  }
}
