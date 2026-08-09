package servlets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class SetupTest {

  private static final String VALID_AUTH = "a1b2c3d4-0000-0000-0000-000000000000";

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

  // The host is concatenated into "jdbc:mariadb://host:port/" and the options are appended after a
  // "?", so a host carrying "?" or "&" can append arbitrary JDBC properties and redirect the
  // connection to a server the requester controls.

  @Test
  public void validateHostPort_hostSmugglingJdbcProperty_isInvalid() {
    assertNotNull(Setup.validateHostPort("evil.example.com?allowLoadLocalInfile=true", "3306"));
  }

  @Test
  public void validateHostPort_hostSmugglingExtraParameter_isInvalid() {
    assertNotNull(Setup.validateHostPort("db.example.com&autoDeserialize=true", "3306"));
  }

  @Test
  public void validateHostPort_hostWithPathSeparator_isInvalid() {
    assertNotNull(Setup.validateHostPort("db.example.com/other", "3306"));
  }

  @Test
  public void validateHostPort_hostWithWhitespace_isInvalid() {
    assertNotNull(Setup.validateHostPort("db.example.com ", "3306"));
  }

  @Test
  public void validateHostPort_ipv4Host_isValid() {
    assertNull(Setup.validateHostPort("127.0.0.1", "3306"));
  }

  @Test
  public void validateHostPort_bracketedIpv6Host_isValid() {
    assertNull(Setup.validateHostPort("[::1]", "3306"));
  }

  @Test
  public void validateHostPort_nonNumericPort_isInvalid() {
    assertNotNull(Setup.validateHostPort("localhost", "notaport"));
  }

  @Test
  public void validateHostPort_portOutOfRange_isInvalid() {
    assertNotNull(Setup.validateHostPort("localhost", "70000"));
  }

  // A successful install deletes the auth file, so on an installed instance the token read comes
  // back empty. Treating that as a match would let anyone POST an empty dbauth and re-run the
  // schema, destroying every user and score.

  @Test
  public void isAuthorised_missingAuthFileAndEmptySuppliedToken_isRejected() {
    assertFalse(Setup.isAuthorised(null, ""));
  }

  @Test
  public void isAuthorised_emptyExpectedAndEmptySupplied_isRejected() {
    assertFalse(Setup.isAuthorised("", ""));
  }

  @Test
  public void isAuthorised_missingAuthFileAndNullSuppliedToken_isRejected() {
    assertFalse(Setup.isAuthorised(null, null));
  }

  @Test
  public void isAuthorised_blankSuppliedToken_isRejected() {
    assertFalse(Setup.isAuthorised(VALID_AUTH, "   "));
  }

  @Test
  public void isAuthorised_wrongToken_isRejected() {
    assertFalse(Setup.isAuthorised(VALID_AUTH, "00000000-0000-0000-0000-000000000000"));
  }

  @Test
  public void isAuthorised_correctToken_isAccepted() {
    assertTrue(Setup.isAuthorised(VALID_AUTH, VALID_AUTH));
  }

  @Test
  public void isAuthorised_correctTokenWithSurroundingWhitespace_isAccepted() {
    assertTrue(Setup.isAuthorised(VALID_AUTH, "  " + VALID_AUTH + "\n"));
  }
}
