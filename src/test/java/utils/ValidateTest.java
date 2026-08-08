package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class ValidateTest {

  private static String chars(char c, int count) {
    char[] arr = new char[count];
    Arrays.fill(arr, c);
    return new String(arr);
  }

  // cookie lookup

  @Test
  void getToken_noCookieHeaderReturnsNull() {
    assertNull(Validate.getToken(null));
  }

  @Test
  void getSessionId_noCookieHeaderReturnsNull() {
    assertNull(Validate.getSessionId(null));
  }

  @Test
  void getToken_ignoresUnrelatedCookies() {
    Cookie[] cookies = {new Cookie("preference", "compact")};
    assertNull(Validate.getToken(cookies));
  }

  @Test
  void getSessionId_findsSessionCookie() {
    Cookie expected = new Cookie("JSESSIONID", "session-value");
    Cookie[] cookies = {new Cookie("preference", "compact"), expected};
    assertEquals(expected, Validate.getSessionId(cookies));
  }

  @Test
  void validateTokens_requiresRequestCookieAndSessionToMatch() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("csrfToken")).thenReturn("1234567890123456");

    assertTrue(
        Validate.validateTokens(
            session, new Cookie("token", "1234567890123456"), "1234567890123456"));
  }

  @Test
  void validateTokens_rejectsClientControlledPairNotBoundToSession() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("csrfToken")).thenReturn("server-token");

    assertFalse(
        Validate.validateTokens(session, new Cookie("token", "attacker-token"), "attacker-token"));
  }

  @Test
  void validateTokens_rejectsUnexpectedRequestTokenType() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("csrfToken")).thenReturn("1234567890123456");

    assertFalse(
        Validate.validateTokens(session, new Cookie("token", "1234567890123456"), new Object()));
  }

  @Test
  void validateSessionToken_requiresRequestToMatchSession() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("csrfToken")).thenReturn("registration-token");

    assertTrue(Validate.validateSessionToken(session, "registration-token"));
    assertFalse(Validate.validateSessionToken(session, "attacker-token"));
    assertFalse(Validate.validateSessionToken(session, null));
  }

  // validateParameter

  @Test
  void validateParameter_nullReturnsEmpty() {
    assertEquals("", Validate.validateParameter(null, 100));
  }

  @Test
  void validateParameter_withinLimitReturnsValue() {
    assertEquals("hello", Validate.validateParameter("hello", 10));
  }

  @Test
  void validateParameter_exceedsLimitReturnsEmpty() {
    assertEquals("", Validate.validateParameter("toolong", 3));
  }

  @Test
  void validateParameter_exactLimitReturnsValue() {
    assertEquals("abc", Validate.validateParameter("abc", 3));
  }

  @Test
  void validateParameter_emptyStringReturnsEmpty() {
    assertEquals("", Validate.validateParameter("", 10));
  }

  @Test
  void validateParameter_unexpectedTypeReturnsEmpty() {
    assertEquals("", Validate.validateParameter(new Object(), 10));
  }

  // isValidPassword

  @Test
  void isValidPassword_tooShort() {
    assertFalse(Validate.isValidPassword("1234567"));
  }

  @Test
  void isValidPassword_minimumValid() {
    assertTrue(Validate.isValidPassword("12345678"));
  }

  @Test
  void isValidPassword_maximumValid() {
    assertTrue(Validate.isValidPassword(chars('a', 512)));
  }

  @Test
  void isValidPassword_tooLong() {
    assertFalse(Validate.isValidPassword(chars('a', 513)));
  }

  @Test
  void isValidPassword_empty() {
    assertFalse(Validate.isValidPassword(""));
  }

  @Test
  void isValidPassword_null() {
    assertFalse(Validate.isValidPassword(null));
  }

  // isValidUser (2 params)

  @Test
  void isValidUser_validCredentials() {
    assertTrue(Validate.isValidUser("bob", "password1"));
  }

  @Test
  void isValidUser_usernameTooShort() {
    assertFalse(Validate.isValidUser("ab", "password1"));
  }

  @Test
  void isValidUser_usernameTooLong() {
    assertFalse(Validate.isValidUser(chars('a', 33), "password1"));
  }

  @Test
  void isValidUser_passwordTooShort() {
    assertFalse(Validate.isValidUser("bob", "1234567"));
  }

  @Test
  void isValidUser_maxUsername() {
    assertTrue(Validate.isValidUser(chars('a', 32), "password1"));
  }

  @Test
  void isValidUser_rejectsNullAndControlCharacters() {
    assertFalse(Validate.isValidUser(null, "password1"));
    assertFalse(Validate.isValidUser("bob", null));
    assertFalse(Validate.isValidUser("bob\nadmin", "password1"));
    assertFalse(Validate.isValidUser("<script>", "password1"));
  }

  // isValidUser (3 params)

  @Test
  void isValidUserWithAddress_valid() {
    assertTrue(Validate.isValidUser("bob", "password1", "123 Main St"));
  }

  @Test
  void isValidUserWithAddress_addressTooLong() {
    assertFalse(Validate.isValidUser("bob", "password1", chars('a', 129)));
  }

  @Test
  void isValidUserWithAddress_maxAddress() {
    assertTrue(Validate.isValidUser("bob", "password1", chars('a', 128)));
  }

  @Test
  void isValidUserWithAddress_rejectsNullsAndControlCharacters() {
    assertFalse(Validate.isValidUser(null, "password1", "address"));
    assertFalse(Validate.isValidUser("bob", null, "address"));
    assertFalse(Validate.isValidUser("bob", "password1", null));
    assertFalse(Validate.isValidUser("bob", "password1", "line1\nline2"));
  }

  // validateEncryptionKey

  @Test
  void validateEncryptionKey_exactLength() {
    String key = "1234567890123456";
    assertEquals(key, Validate.validateEncryptionKey(key));
  }

  @Test
  void validateEncryptionKey_tooLongTruncated() {
    String key = "12345678901234567890";
    String result = Validate.validateEncryptionKey(key);
    assertEquals(16, result.length());
    assertEquals("1234567890123456", result);
  }

  @Test
  void validateEncryptionKey_shortKeyPadded() {
    String result = Validate.validateEncryptionKey("abcd");
    assertEquals(16, result.length());
  }

  @Test
  void validateEncryptionKey_singleCharPadded() {
    String result = Validate.validateEncryptionKey("x");
    assertEquals(16, result.length());
  }

  @Test
  void validateEncryptionKey_eightCharPadded() {
    String result = Validate.validateEncryptionKey("12345678");
    assertEquals(16, result.length());
  }

  // makeValidUrl

  @Test
  void makeValidUrl_addsHttpPrefix() {
    assertEquals("http://example.com", Validate.makeValidUrl("://example.com"));
  }

  @Test
  void makeValidUrl_alreadyHttp() {
    assertEquals("http://example.com", Validate.makeValidUrl("http://example.com"));
  }

  @Test
  void makeValidUrl_httpsUnchanged() {
    assertEquals("https://example.com", Validate.makeValidUrl("https://example.com"));
  }

  @Test
  void makeValidUrl_lowercases() {
    assertEquals("http://example.com", Validate.makeValidUrl("HTTP://EXAMPLE.COM"));
  }

  // validHostUrl

  @Test
  void validHostUrl_endsWithSlash() {
    assertTrue(Validate.validHostUrl("http://example.com/"));
  }

  @Test
  void validHostUrl_noTrailingSlash() {
    assertFalse(Validate.validHostUrl("http://example.com"));
  }

  @Test
  void validHostUrl_null() {
    assertFalse(Validate.validHostUrl(null));
  }

  // isValidPortNumber

  @Test
  void isValidPortNumber_validPort() {
    assertTrue(Validate.isValidPortNumber("8080"));
  }

  @Test
  void isValidPortNumber_minPort() {
    assertTrue(Validate.isValidPortNumber("1"));
  }

  @Test
  void isValidPortNumber_maxPort() {
    assertTrue(Validate.isValidPortNumber("65535"));
  }

  @Test
  void isValidPortNumber_zero() {
    assertFalse(Validate.isValidPortNumber("0"));
  }

  @Test
  void isValidPortNumber_aboveMax() {
    assertFalse(Validate.isValidPortNumber("65536"));
  }

  @Test
  void isValidPortNumber_nonNumeric() {
    assertFalse(Validate.isValidPortNumber("abc"));
  }

  @Test
  void isValidPortNumber_negative() {
    assertFalse(Validate.isValidPortNumber("-1"));
  }

  @Test
  void isValidPortNumber_null() {
    assertFalse(Validate.isValidPortNumber(null));
  }

  // isValidEmailAddress

  @Test
  void isValidEmailAddress_valid() {
    assertTrue(Validate.isValidEmailAddress("test@example.com"));
  }

  @Test
  void isValidEmailAddress_invalid() {
    assertFalse(Validate.isValidEmailAddress("not-an-email"));
  }

  @Test
  void isValidEmailAddress_empty() {
    assertFalse(Validate.isValidEmailAddress(""));
  }

  @Test
  void isValidEmailAddress_null() {
    assertFalse(Validate.isValidEmailAddress(null));
  }

  // isValidClassYear

  @Test
  void isValidClassYear_validYear() {
    assertTrue(Validate.isValidClassYear("2024"));
  }

  @Test
  void isValidClassYear_tooShort() {
    assertFalse(Validate.isValidClassYear("24"));
  }

  @Test
  void isValidClassYear_tooLong() {
    assertFalse(Validate.isValidClassYear("20240"));
  }

  @Test
  void isValidClassYear_atBoundary() {
    assertFalse(Validate.isValidClassYear("2010"));
  }

  @Test
  void isValidClassYear_justAboveBoundary() {
    assertTrue(Validate.isValidClassYear("2011"));
  }

  @Test
  void isValidClassYear_nonNumericFourChars() {
    assertFalse(Validate.isValidClassYear("abcd"));
  }

  @Test
  void isValidClassYear_null() {
    assertFalse(Validate.isValidClassYear(null));
  }

  @Test
  void validateSession_requiresRoleAndUsername() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userRole")).thenReturn("player");

    assertFalse(Validate.validateSession(session));
  }
}
