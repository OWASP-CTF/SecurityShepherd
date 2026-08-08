package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class XxeChallenge1OldWebServiceTest {

  @Test
  void rejectsExternalEntityDocuments(@TempDir Path tempDirectory) throws Exception {
    Path secret = tempDirectory.resolve("server-secret.txt");
    Files.write(secret, "must-not-be-read".getBytes(StandardCharsets.UTF_8));
    String xml =
        "<!DOCTYPE email [<!ENTITY xxe SYSTEM \"" + secret.toUri() + "\">]><email>&xxe;</email>";

    assertNull(XxeChallenge1OldWebService.readXml(input(xml)));
  }

  @Test
  void preservesOrdinaryEmailDocuments() {
    assertEquals(
        "player@example.com",
        XxeChallenge1OldWebService.readXml(input("<email>player@example.com</email>")));
  }

  private static ByteArrayInputStream input(String xml) {
    return new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
  }
}
