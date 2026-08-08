package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class CsrfChallengeSecurityTest {

  @Test
  void counterWriteBelongsToTheAuthenticatedUser() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userStamp")).thenReturn("victim-user");

    assertEquals("victim-user", CsrfChallengeSecurity.counterOwner(session, "attacker-user"));
  }

  @Test
  void selfTargetingDoesNotCompleteTheChallenge() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userStamp")).thenReturn("authenticated-user");

    assertNull(CsrfChallengeSecurity.counterOwner(session, "authenticated-user"));
  }

  @Test
  void tokenLookupBelongsToTheAuthenticatedUser() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userStamp")).thenReturn("authenticated-user");

    assertEquals("authenticated-user", CsrfChallengeSecurity.authenticatedUserId(session));
  }
}
