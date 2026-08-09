package servlets.module;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class SqlInjectionQuerySafetyTest {

  @Test
  void sqlInjectionModulesBindRequestDataInsteadOfConcatenatingIt() throws IOException {
    List<String> modules =
        Arrays.asList(
            "SqlInjection1",
            "SqlInjection3",
            "SqlInjection4",
            "SqlInjection5",
            "SqlInjection5CouponCheck",
            "SqlInjection5VipCheck",
            "SqlInjection6",
            "SqlInjection7",
            "SqlInjectionEmail",
            "SqlInjectionEscaping",
            "SqlInjectionStoredProcedure");

    for (String module : modules) {
      Path sourcePath = Paths.get("src/main/java/servlets/module/challenge", module + ".java");
      String source = new String(Files.readAllBytes(sourcePath), StandardCharsets.UTF_8);

      assertFalse(source.contains(".createStatement()"), module + " uses a raw SQL statement");
      assertTrue(
          source.contains(".prepareStatement(") || source.contains(".prepareCall("),
          module + " does not prepare its query");
      assertTrue(source.contains("?"), module + " does not contain a bind placeholder");
    }
  }
}
