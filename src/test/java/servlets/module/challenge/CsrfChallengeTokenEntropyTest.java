package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class CsrfChallengeTokenEntropyTest {

  private static final Set<String> KNOWN_WEAK_TOKENS =
      new HashSet<>(
          Arrays.asList(
              "0",
              "1",
              "2",
              "c4ca4238a0b923820dcc509a6f75849b",
              "c81e728d9d4c2f636f067f89cc14862c",
              "eccbc87e4b5ce2fe28308fd9f2a7baf3"));

  @Test
  void challengeFiveMintsAnUnpredictableToken() throws Exception {
    RequestFixture fixture = new RequestFixture("csrfChallengeFiveNonce");

    new CsrfChallengeTargetFive().doPost(fixture.request, fixture.response);

    fixture.assertStrongTokenStored();
  }

  @Test
  void challengeSixMintsAnUnpredictableToken() throws Exception {
    RequestFixture fixture = new RequestFixture("csrfChallengeSixNonce");

    new CsrfChallengeTargetSix().doPost(fixture.request, fixture.response);

    fixture.assertStrongTokenStored();
  }

  private static final class RequestFixture {
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final HttpSession session = mock(HttpSession.class);
    private final String tokenAttribute;

    private RequestFixture(String tokenAttribute) throws Exception {
      this.tokenAttribute = tokenAttribute;
      when(request.getSession()).thenReturn(session);
      when(request.getSession(true)).thenReturn(session);
      when(request.getRemoteAddr()).thenReturn("127.0.0.1");
      when(request.getParameter("userId")).thenReturn("authenticated-user");
      when(request.getParameter("csrfToken")).thenReturn("");
      when(session.getAttribute("userRole")).thenReturn("player");
      when(session.getAttribute("userName")).thenReturn("security-test");
      when(session.getAttribute("userStamp")).thenReturn("authenticated-user");
      when(session.getAttribute(tokenAttribute)).thenReturn(null);
      when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
    }

    private void assertStrongTokenStored() {
      ArgumentCaptor<Object> token = ArgumentCaptor.forClass(Object.class);
      verify(session).setAttribute(eq(tokenAttribute), token.capture());
      assertFalse(KNOWN_WEAK_TOKENS.contains(token.getValue().toString()));
    }
  }
}
