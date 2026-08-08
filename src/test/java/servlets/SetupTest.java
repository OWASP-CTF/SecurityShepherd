package servlets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class SetupTest {

  @Test
  public void validateHostPort_bothEmpty_isValid() {
    assertNull(Setup.validateHostPort("", ""));
  }

  @Test
  public void validateHostPort_bothProvided_isValid() {
    assertNull(Setup.validateHostPort("localhost", "3306"));
  }

  @Test
  public void validateHostPort_onlyHostProvided_isInvalid() {
    assertNotNull(Setup.validateHostPort("localhost", ""));
  }

  @Test
  public void validateHostPort_onlyPortProvided_isInvalid() {
    assertNotNull(Setup.validateHostPort("", "3306"));
  }

  @Test
  public void validateHostPort_bothNull_isValid() {
    assertNull(Setup.validateHostPort(null, null));
  }

  @Test
  public void validateHostPort_hostNullPortProvided_isInvalid() {
    assertNotNull(Setup.validateHostPort(null, "3306"));
  }

  @Test
  public void validateHostPort_hostProvidedPortNull_isInvalid() {
    assertNotNull(Setup.validateHostPort("localhost", null));
  }

  @Test
  public void authorizationMatches_requiresExactNonNullValue() {
    assertTrue(Setup.authorizationMatches("server-secret", "server-secret"));
    assertFalse(Setup.authorizationMatches("server-secret", "SERVER-SECRET"));
    assertFalse(Setup.authorizationMatches("", ""));
    assertFalse(Setup.authorizationMatches("server-secret", ""));
    assertFalse(Setup.authorizationMatches("server-secret", null));
    assertFalse(Setup.authorizationMatches(null, "server-secret"));
  }

  @Test
  public void databaseHost_rejectsJdbcAndPropertyInjectionCharacters() {
    assertTrue(Setup.isValidDatabaseHost("database.internal"));
    assertTrue(Setup.isValidDatabaseHost("127.0.0.1"));
    assertTrue(Setup.isValidDatabaseHost("[2001:db8::1]"));

    assertFalse(Setup.isValidDatabaseHost(""));
    assertFalse(Setup.isValidDatabaseHost("database/otherSchema"));
    assertFalse(Setup.isValidDatabaseHost("database?allowMultiQueries=true"));
    assertFalse(Setup.isValidDatabaseHost("database\nDriverType=evil"));
  }
}
