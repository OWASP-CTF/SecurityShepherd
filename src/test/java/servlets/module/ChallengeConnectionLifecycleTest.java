package servlets.module;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ChallengeConnectionLifecycleTest {

  private static final String ACQUIRE = "Database.getChallengeConnection(";
  private static final String RELEASE = "Database.closeConnection(conn);";

  @Test
  void everyChallengeConnectionIsReleasedFromFinally() throws IOException {
    Path moduleSources = Paths.get("src/main/java/servlets/module");
    int acquisitions = 0;

    try (Stream<Path> paths = Files.walk(moduleSources)) {
      for (Path path :
          (Iterable<Path>) paths.filter(p -> p.toString().endsWith(".java"))::iterator) {
        String source = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        int fileAcquisitions = occurrences(source, ACQUIRE);
        if (fileAcquisitions == 0) {
          continue;
        }

        acquisitions += fileAcquisitions;
        int finallyReleases =
            occurrences(source.replaceAll("finally\\s*\\{\\s*", "finally{"), "finally{" + RELEASE);

        assertTrue(
            finallyReleases >= fileAcquisitions,
            path + " acquires a pooled connection without releasing it from finally");
        assertEquals(0, occurrences(source, "conn.close()"), path + " bypasses Database cleanup");
      }
    }

    assertEquals(36, acquisitions, "update the lifecycle census when adding connection sites");
  }

  private static int occurrences(String source, String target) {
    int count = 0;
    int offset = 0;
    while ((offset = source.indexOf(target, offset)) >= 0) {
      count++;
      offset += target.length();
    }
    return count;
  }
}
