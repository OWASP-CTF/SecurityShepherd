package servlets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RegisterTest {

  @Test
  void registration_acceptsMatchingValidFieldsAndOptionalBlankEmail() {
    assertTrue(
        Register.validRegistrationFields(
            "alice", "correct horse", "correct horse", "alice@example.com", "alice@example.com"));
    assertTrue(Register.validRegistrationFields("alice", "correct horse", "correct horse", "", ""));
  }

  @Test
  void registration_rejectsMissingMismatchedOrMalformedFields() {
    assertFalse(
        Register.validRegistrationFields(
            "alice", "correct horse", null, "alice@example.com", "alice@example.com"));
    assertFalse(
        Register.validRegistrationFields(
            "alice", "correct horse", "different", "alice@example.com", "alice@example.com"));
    assertFalse(
        Register.validRegistrationFields(
            "alice", "correct horse", "correct horse", "not-an-email", "not-an-email"));
    assertFalse(
        Register.validRegistrationFields(
            "alice", "correct horse", "correct horse", "alice@example.com", "eve@example.com"));
  }
}
