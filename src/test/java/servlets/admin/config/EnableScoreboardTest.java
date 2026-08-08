package servlets.admin.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class EnableScoreboardTest {

  @Test
  void requestedMode_mapsEverySupportedConfiguration() {
    assertEquals(EnableScoreboard.ScoreboardMode.OPEN, EnableScoreboard.requestedMode("", null));
    assertEquals(
        EnableScoreboard.ScoreboardMode.PUBLIC, EnableScoreboard.requestedMode("", "false"));
    assertEquals(
        EnableScoreboard.ScoreboardMode.ADMIN_ONLY, EnableScoreboard.requestedMode("", "true"));
    assertEquals(
        EnableScoreboard.ScoreboardMode.CLASS_SPECIFIC,
        EnableScoreboard.requestedMode("classSpecific", null));
    assertEquals(
        EnableScoreboard.ScoreboardMode.SELECTED_CLASS,
        EnableScoreboard.requestedMode("class-123", null));
    assertEquals(
        EnableScoreboard.ScoreboardMode.ADMIN_ONLY,
        EnableScoreboard.requestedMode("class-123", "true"));
  }

  @Test
  void requestedMode_rejectsMissingOrAmbiguousConfiguration() {
    assertEquals(
        EnableScoreboard.ScoreboardMode.INVALID, EnableScoreboard.requestedMode(null, null));
    assertEquals(
        EnableScoreboard.ScoreboardMode.INVALID, EnableScoreboard.requestedMode("", "TRUE"));
    assertEquals(
        EnableScoreboard.ScoreboardMode.INVALID,
        EnableScoreboard.requestedMode("classSpecific", "true"));
    assertEquals(
        EnableScoreboard.ScoreboardMode.INVALID,
        EnableScoreboard.requestedMode("class\nforged", null));
  }
}
