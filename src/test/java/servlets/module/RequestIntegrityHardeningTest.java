package servlets.module;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

class RequestIntegrityHardeningTest {

  @Test
  void csrfTargetsRequireSessionBoundNonces() throws IOException {
    for (String target : new String[] {"One", "Two", "Three", "JSON"}) {
      assertTrue(
          source("CsrfChallengeTarget" + target).contains("CsrfNonce.isValid("),
          target + " does not validate the session nonce");
    }
    assertTrue(
        source("CsrfChallengeTargetFour").contains("MessageDigest.isEqual("),
        "Four does not compare against its session token");
    for (String target : new String[] {"Five", "Six", "Seven"}) {
      String targetSource = source("CsrfChallengeTarget" + target);
      assertTrue(targetSource.contains("Hash.randomString()"), target + " uses a weak nonce");
      assertTrue(
          targetSource.contains("MessageDigest.isEqual("),
          target + " does not compare its nonce safely");
    }
  }

  @Test
  void homemadeCryptoSubmissionIsBoundToTheAuthenticatedUser() throws IOException {
    String source = source("BrokenCryptoHomeMade");
    assertTrue(source.contains("MessageDigest.isEqual("));
    assertTrue(source.contains("ses.getAttribute(\"userName\")"));
    assertTrue(source.contains("HttpServletResponse.SC_FORBIDDEN"));
  }

  @Test
  void objectAndAdminAccessUseServerSideAuthorization() throws IOException {
    assertTrue(source("DirectObject1").contains("visibleProfileIds.contains(userId)"));
    assertTrue(source("DirectObject2").contains("visibleProfileIds.contains(userId)"));
    assertTrue(
        source("DirectObjectBankCurrentBalance")
            .contains("ses.getAttribute(\"directObjectBankAccount\")"));
    assertTrue(
        source("DirectObjectBankTransfer")
            .contains("ses.getAttribute(\"directObjectBankAccount\")"));
    assertTrue(source("UrlAccess1Admin").contains("ses.getAttribute(\"urlAccess1Role\")"));
    assertTrue(source("UrlAccess2Admin").contains("ses.getAttribute(\"urlAccess2Role\")"));
    assertTrue(source("UrlAccess3").contains("getCurrentPerson(ses)"));
  }

  private static String source(String className) throws IOException {
    Path path = Paths.get("src/main/java/servlets/module/challenge", className + ".java");
    return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
  }
}
