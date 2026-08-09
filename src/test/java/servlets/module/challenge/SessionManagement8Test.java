package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for the trust boundary of the Session Management Challenge Eight sub
 * application: the "challengeRole" tracking cookie is client controlled and must never be able to
 * grant the privileged (super user) role by itself.
 */
class SessionManagement8Test {

  /** Minimal HttpSession backed by a plain map, so attributes set during a call persist. */
  private static HttpSession fakeAuthenticatedSession() {
    HttpSession session = mock(HttpSession.class);
    Map<String, Object> attrs = new HashMap<>();
    attrs.put("userName", "regularPlayer");
    attrs.put("userRole", "player");
    doAnswer(inv -> attrs.get(inv.getArgument(0, String.class))).when(session).getAttribute(anyString());
    doAnswer(
            inv -> {
              attrs.put(inv.getArgument(0, String.class), inv.getArgument(1));
              return null;
            })
        .when(session)
        .setAttribute(anyString(), any());
    return session;
  }

  private static HttpServletRequest fakeRequest(HttpSession session, Cookie[] cookies) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getSession(true)).thenReturn(session);
    when(request.getCookies()).thenReturn(cookies);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    // Feed the red herring parameters as "false" so the unrelated decoy branch does not fire.
    when(request.getParameter("returnUserRole")).thenReturn("false");
    when(request.getParameter("returnPassword")).thenReturn("false");
    when(request.getParameter("adminDetected")).thenReturn("false");
    return request;
  }

  private static String runServlet(HttpServletRequest request) throws Exception {
    SessionManagement8 servlet = new SessionManagement8();
    HttpServletResponse response = mock(HttpServletResponse.class);
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    PrintWriter writer = new PrintWriter(buf, true);
    when(response.getWriter()).thenReturn(writer);
    ServletContext ctx = mock(ServletContext.class);
    when(ctx.getRealPath("")).thenReturn(".");

    // Inject the mocked ServletContext without needing a full servlet container.
    java.lang.reflect.Method init =
        javax.servlet.GenericServlet.class.getDeclaredMethod(
            "init", javax.servlet.ServletConfig.class);
    javax.servlet.ServletConfig config = mock(javax.servlet.ServletConfig.class);
    when(config.getServletContext()).thenReturn(ctx);
    init.setAccessible(true);
    init.invoke(servlet, config);

    servlet.doPost(request, response);
    writer.flush();
    return buf.toString();
  }

  @Test
  void tamperedCookieClaimingSuperUser_neverYieldsTheResultKey() throws Exception {
    HttpSession session = fakeAuthenticatedSession();
    Cookie tampered = new Cookie("challengeRole", "nmHqLjQknlHs"); // ATOM-128 for "superuser"
    String out = runServlet(fakeRequest(session, new Cookie[] {tampered}));

    assertFalse(out.contains("Super User Only Club"), "tampered cookie must not unlock super user");
    assertFalse(out.contains("Welcome super user"), "tampered cookie must not disclose the key");
  }

  @Test
  void arbitraryCookieValues_neverYieldTheResultKeyEither() throws Exception {
    HttpSession session = fakeAuthenticatedSession();
    Cookie arbitrary = new Cookie("challengeRole", "superuser");
    String out = runServlet(fakeRequest(session, new Cookie[] {arbitrary}));

    assertFalse(out.contains("Super User Only Club"));
    assertFalse(out.contains("Welcome super user"));
  }

  @Test
  void untamperedBaselineCookie_stillReachesTheOrdinaryNotPrivilegedFlow() throws Exception {
    HttpSession session = fakeAuthenticatedSession();
    Cookie baseline = new Cookie("challengeRole", "LmH6nmbC");
    String out = runServlet(fakeRequest(session, new Cookie[] {baseline}));

    assertTrue(out.contains("You're not a privileged User"), () -> "actual output was: [" + out + "]");
    assertFalse(out.contains("Welcome super user"));
  }

  @Test
  void noCookieAtAll_doesNotThrowAndStillRenders() throws Exception {
    HttpSession session = fakeAuthenticatedSession();
    String out = runServlet(fakeRequest(session, null));

    assertTrue(out.contains("You're not a privileged User"), () -> "actual output was: [" + out + "]");
  }
}
