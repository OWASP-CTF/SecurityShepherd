package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionManagement7SecretQuestionTest {

  @Test
  void knownAdministratorFlowerCannotRecoverResultKey() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    StringWriter body = new StringWriter();

    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("subEmail")).thenReturn("elitehacker@shepherd.com");
    when(request.getParameter("subAnswer")).thenReturn("Franklin Tree");
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("security-test");
    when(response.getWriter()).thenReturn(new PrintWriter(body));

    new SessionManagement7SecretQuestion().doPost(request, response);

    assertTrue(body.toString().contains("Incorrect Answer"));
    assertFalse(body.toString().contains("The result key is"));
  }
}
