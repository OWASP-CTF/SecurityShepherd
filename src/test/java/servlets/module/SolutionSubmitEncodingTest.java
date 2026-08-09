package servlets.module;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

class SolutionSubmitEncodingTest {

  @Test
  void feedbackFormDoesNotEmbedUntrustedValuesAsJavaScript() throws Exception {
    String injection = "\";alert(1);//</script><script>alert(2)</script>";
    Method generateFeedbackForm =
        SolutionSubmit.class.getDeclaredMethod(
            "generateFeedbackForm", String.class, String.class, String.class);
    generateFeedbackForm.setAccessible(true);

    String form =
        (String) generateFeedbackForm.invoke(null, injection, injection, injection);

    assertFalse(form.contains(injection));
    assertFalse(form.contains("</script><script>alert(2)</script>"));
  }
}
