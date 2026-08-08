package servlets.module;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FeedbackSubmitTest {

  @Test
  void ratings_areRestrictedToTheRenderedFormRange() {
    assertEquals(0, FeedbackSubmit.parseRating("0"));
    assertEquals(5, FeedbackSubmit.parseRating("5"));
    assertNull(FeedbackSubmit.parseRating(null));
    assertNull(FeedbackSubmit.parseRating("6"));
    assertNull(FeedbackSubmit.parseRating("-1"));
    assertNull(FeedbackSubmit.parseRating("not-a-number"));
  }

  @Test
  void solutionComparison_isExactAndNullSafe() {
    assertTrue(FeedbackSubmit.secretsEqual("solution-key", "solution-key"));
    assertFalse(FeedbackSubmit.secretsEqual("solution-key", "SOLUTION-KEY"));
    assertFalse(FeedbackSubmit.secretsEqual("solution-key", null));
  }

  @Test
  void refreshScript_usesJavaScriptContextEncoding() {
    String output = FeedbackSubmit.refreshMenuScript("token\";alert(1)//", "error\nmessage");

    assertFalse(output.contains("token\";alert"));
    assertFalse(output.contains("error\nmessage"));
    assertTrue(output.startsWith("<script>refreshSideMenu("));
  }
}
