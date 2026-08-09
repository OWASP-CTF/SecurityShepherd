package servlets.module;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

class SessionAndDataHardeningTest {

  @Test
  void miscellaneousChallengesUseNonExploitablePrimitives() throws IOException {
    assertTrue(source("BrokenCrypto3").contains("AES/GCM/NoPadding"));
    assertTrue(source("NoSqlInjection1").contains("new BasicDBObject(\"_id\", gamerId)"));
    assertFalse(source("NoSqlInjection1").contains("$where"));
    assertTrue(source("PoorValidation1").contains("Math.multiplyExact("));
    assertTrue(source("PoorValidation2").contains("Math.multiplyExact("));
  }

  @Test
  void sessionChallengesKeepAuthorityAndRecoverySecretsServerSide() throws IOException {
    assertTrue(source("SessionManagement1").contains("ses.getAttribute(SUB_ROLE)"));
    assertTrue(source("SessionManagement4").contains("ses.getAttribute(SUB_ROLE)"));
    assertTrue(source("SessionManagement8").contains("ses.getAttribute(SUB_ROLE)"));
    assertTrue(
        source("SessionManagement3ChangePassword")
            .contains("ses.getAttribute(SessionManagement3.SUB_USER)"));
    assertTrue(source("SessionManagement5SetToken").contains("Hash.randomString()"));
    assertTrue(source("SessionManagement5ChangePassword").contains("MessageDigest.isEqual("));
    assertFalse(source("SessionManagement6SecretQuestion").contains("Hash.generateUserSolution("));
    assertFalse(source("SessionManagement7SecretQuestion").contains("Hash.generateUserSolution("));
  }

  private static String source(String className) throws IOException {
    Path path = Paths.get("src/main/java/servlets/module/challenge", className + ".java");
    return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
  }
}
