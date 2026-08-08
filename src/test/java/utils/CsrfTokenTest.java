package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.servlet.http.Cookie;
import org.junit.jupiter.api.Test;

class CsrfTokenTest {

  @Test
  void createCookie_setsPlatformSecurityAttributes() {
    Cookie cookie = CsrfToken.createCookie("token-value", true, "/shepherd");

    assertEquals("token", cookie.getName());
    assertEquals("token-value", cookie.getValue());
    assertEquals("/shepherd", cookie.getPath());
    assertTrue(cookie.getSecure());
    assertTrue(cookie.isHttpOnly());
  }

  @Test
  void createCookie_supportsLocalHttpDevelopment() {
    Cookie cookie = CsrfToken.createCookie("token-value", false, "");

    assertEquals("/", cookie.getPath());
    assertFalse(cookie.getSecure());
    assertTrue(cookie.isHttpOnly());
  }

  @Test
  void expiredCookie_deletesTheApplicationCookie() {
    Cookie cookie = CsrfToken.expiredCookie(true, "/shepherd");

    assertEquals("", cookie.getValue());
    assertEquals(0, cookie.getMaxAge());
    assertEquals("/shepherd", cookie.getPath());
    assertTrue(cookie.getSecure());
    assertTrue(cookie.isHttpOnly());
  }
}
