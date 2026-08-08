package servlets.admin.userManagement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AdminInputValidationTest {

  @Test
  void suspensionDuration_rejectsMissingMalformedAndNonPositiveValues() {
    assertEquals(30, SuspendUser.parsePositiveInt("30"));
    assertEquals(-1, SuspendUser.parsePositiveInt(null));
    assertEquals(-1, SuspendUser.parsePositiveInt("not-a-number"));
    assertEquals(-1, SuspendUser.parsePositiveInt("0"));
    assertEquals(-1, SuspendUser.parsePositiveInt("-30"));
  }

  @Test
  void scoreDelta_rejectsMissingMalformedAndZeroValues() {
    assertEquals(25, GiveTakePoints.parseNonZeroInt("25"));
    assertEquals(-25, GiveTakePoints.parseNonZeroInt("-25"));
    assertNull(GiveTakePoints.parseNonZeroInt(null));
    assertNull(GiveTakePoints.parseNonZeroInt("not-a-number"));
    assertNull(GiveTakePoints.parseNonZeroInt("0"));
  }
}
