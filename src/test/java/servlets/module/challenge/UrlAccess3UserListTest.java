package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class UrlAccess3UserListTest {

  @Test
  void defaultsToGuestWithoutServerSideIdentity() {
    HttpSession session = mock(HttpSession.class);

    assertEquals("aGuest", UrlAccess3UserList.getSimulatedUser(session));
  }

  @Test
  void usesOnlyServerSideSessionIdentity() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("urlAccess3SimulatedUser")).thenReturn("serverSelectedUser");

    assertEquals("serverSelectedUser", UrlAccess3UserList.getSimulatedUser(session));
  }
}
