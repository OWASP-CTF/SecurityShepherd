package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionManagement6SecretQuestionTest {

  @Test
  void knownAdministratorAnswerCannotRecoverResultKey() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    StringWriter body = new StringWriter();

    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("subEmail")).thenReturn("elitehacker@shepherd.com");
    when(request.getParameter("subAnswer")).thenReturn("Deerburn Hotel");
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("security-test");
    when(response.getWriter()).thenReturn(new PrintWriter(body));

    new SessionManagement6SecretQuestion().doPost(request, response);

    assertTrue(body.toString().contains("Incorrect Answer"));
    assertFalse(body.toString().contains("The result key is"));
  }

  @Test
  void recoveryQuestionResponseDoesNotEnumerateAccounts() throws Exception {
    String knownUser = getQuestion("elitehacker@shepherd.com");
    String unknownUser = getQuestion("unknown@example.invalid");

    assertTrue(knownUser.contains("No question"));
    assertTrue(knownUser.equals(unknownUser));
  }

  private static String getQuestion(String email) throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    StringWriter body = new StringWriter();

    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("ac", "ZG9Ob3RSZXR1cm5BbnN3ZXJz")});
    when(request.getParameter("subEmail")).thenReturn(email);
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("security-test");
    when(response.getWriter()).thenReturn(new PrintWriter(body));

    new SessionManagement6SecretQuestion().doGet(request, response);
    return body.toString();
  }
}
