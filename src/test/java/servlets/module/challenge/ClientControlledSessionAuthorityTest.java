package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class ClientControlledSessionAuthorityTest {

  @Test
  void base64AdministratorCookieDoesNotGrantAuthority() throws Exception {
    RequestFixture fixture =
        new RequestFixture(new Cookie("checksum", "dXNlclJvbGU9YWRtaW5pc3RyYXRvcg=="));

    new SessionManagement1().doPost(fixture.request, fixture.response);

    assertFalse(fixture.body.toString().contains("Welcome administrator"));
  }

  @Test
  void guessedAdministratorSessionIdDoesNotGrantAuthority() throws Exception {
    RequestFixture fixture =
        new RequestFixture(new Cookie("SubSessionID", "TURBd01EQXdNREF3TURBd01EQXdPUT09"));

    new SessionManagement4().doPost(fixture.request, fixture.response);

    assertFalse(fixture.body.toString().contains("Welcome administrator"));
  }

  @Test
  void reversibleSuperuserCookieDoesNotGrantAuthority() throws Exception {
    RequestFixture fixture = new RequestFixture(new Cookie("challengeRole", "nmHqLjQknlHs"));

    new SessionManagement8().doPost(fixture.request, fixture.response);

    assertFalse(fixture.body.toString().contains("Super User Only Club"));
  }

  private static final class RequestFixture {
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final HttpSession session = mock(HttpSession.class);
    private final StringWriter body = new StringWriter();

    private RequestFixture(Cookie cookie) throws Exception {
      when(request.getSession()).thenReturn(session);
      when(request.getSession(true)).thenReturn(session);
      when(request.getRemoteAddr()).thenReturn("127.0.0.1");
      when(request.getCookies()).thenReturn(new Cookie[] {cookie});
      when(session.getAttribute("userRole")).thenReturn("player");
      when(session.getAttribute("userName")).thenReturn("security-test");
      when(response.getWriter()).thenReturn(new PrintWriter(body));
    }
  }
}
