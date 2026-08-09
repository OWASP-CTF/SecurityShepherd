package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

/**
 * Confirms a client-forged "checksum" cookie can no longer promote a request to the administrator
 * response, while a normal, unmodified submission still gets the ordinary non-admin response.
 */
class SessionManagement1Test {

  private static String runWithCookieValue(String rawCookieValue) throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);

    when(session.getAttribute("logout")).thenReturn(null);
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("shepherdTester");
    when(session.getAttribute("lang")).thenReturn(null);

    when(request.getSession(true)).thenReturn(session);
    when(request.getSession()).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getHeader(anyString())).thenReturn(null);

    Cookie checksum =
        new Cookie("checksum", Base64.encodeBase64String(rawCookieValue.getBytes("UTF-8")));
    when(request.getCookies()).thenReturn(new Cookie[] {checksum});

    // Simulate the un-tampered form, which always posts these three fields as "false".
    when(request.getParameter("adminDetected")).thenReturn("false");
    when(request.getParameter("returnPassword")).thenReturn("false");
    when(request.getParameter("upgradeUserToAdmin")).thenReturn("false");

    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    PrintWriter writer = new PrintWriter(captured, true);
    when(response.getWriter()).thenReturn(writer);

    new SessionManagement1().doPost(request, response);
    writer.flush();
    return captured.toString("UTF-8");
  }

  @Test
  void forgedAdministratorCookie_neverYieldsTheAdminResponseOrKey() throws Exception {
    String html = runWithCookieValue("userRole=administrator");
    assertFalse(
        html.contains("Welcome administrator"),
        "A client-supplied cookie must never unlock the administrator response: " + html);
    assertTrue(
        html.contains("You're not an Admin"),
        "Forged cookie should be treated the same as any other non-admin request: " + html);
  }

  @Test
  void genuineUserCookie_stillGetsTheOrdinaryNonAdminResponse() throws Exception {
    String html = runWithCookieValue("userRole=user");
    assertTrue(
        html.contains("You're not an Admin"),
        "Legitimate, untampered submission should still render the normal non-admin message: "
            + html);
    assertFalse(html.contains("Welcome administrator"));
  }
}
