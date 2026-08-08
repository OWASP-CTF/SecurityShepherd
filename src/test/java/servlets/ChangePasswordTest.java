package servlets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ChangePasswordTest {

  @Test
  void validPasswordChange_requiresExactConfirmation() {
    assertFalse(
        ChangePassword.isValidPasswordChange("CurrentPass1", "NewPassword1", "newPassword1"));
  }

  @Test
  void validPasswordChange_allowsCaseOnlyChange() {
    assertTrue(
        ChangePassword.isValidPasswordChange("CurrentPass1", "currentPass1", "currentPass1"));
  }

  @Test
  void validPasswordChange_rejectsMissingValues() {
    assertFalse(ChangePassword.isValidPasswordChange(null, "NewPassword1", "NewPassword1"));
    assertFalse(ChangePassword.isValidPasswordChange("CurrentPass1", null, null));
  }

  @Test
  void validPasswordChange_enforcesPlatformPasswordPolicy() {
    assertFalse(ChangePassword.isValidPasswordChange("CurrentPass1", "short", "short"));
    assertTrue(ChangePassword.isValidPasswordChange("CurrentPass1", "LongEnough", "LongEnough"));
  }
}
