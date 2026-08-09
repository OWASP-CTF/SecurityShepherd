package servlets.module;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

class XssChallengeEncodingTest {

  @Test
  void textSinksUseHtmlEncoding() throws IOException {
    for (String module : new String[] {"One", "Two", "Three"}) {
      String source = source(module);
      assertTrue(source.contains("Encode.forHtml(searchTerm)"), module + " lacks HTML encoding");
      assertFalse(source.contains("XssFilter."), module + " still relies on a blacklist filter");
    }
  }

  @Test
  void uriSinksValidateSchemesAndUseAttributeEncoding() throws IOException {
    for (String module : new String[] {"Four", "Five", "Six"}) {
      String source = source(module);
      assertTrue(
          source.contains("Validate.isHttpUrl(searchTerm)"), module + " accepts unsafe URLs");
      assertTrue(
          source.contains("Encode.forHtmlAttribute(searchTerm)"),
          module + " lacks attribute encoding");
      assertFalse(source.contains("XssFilter."), module + " still relies on a blacklist filter");
    }
  }

  private static String source(String suffix) throws IOException {
    Path path =
        Paths.get("src/main/java/servlets/module/challenge", "XssChallenge" + suffix + ".java");
    return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
  }
}
