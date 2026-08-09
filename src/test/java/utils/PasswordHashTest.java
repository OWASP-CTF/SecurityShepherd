package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class PasswordHashTest {

  @Test
  void hashUsesArgon2AndAUniqueSalt() {
    String firstHash = PasswordHash.hash("correct horse battery staple");
    String secondHash = PasswordHash.hash("correct horse battery staple");

    assertTrue(firstHash.startsWith("$argon2id$"));
    assertNotEquals(firstHash, secondHash);
  }

  @Test
  void verifyAcceptsOnlyTheMatchingPassword() {
    String hash = PasswordHash.hash("a long challenge password");

    assertTrue(PasswordHash.verify(hash, "a long challenge password"));
    assertFalse(PasswordHash.verify(hash, "a different password"));
  }

  @Test
  void verifyRejectsMissingAndMalformedInputs() {
    assertFalse(PasswordHash.verify(null, "password"));
    assertFalse(PasswordHash.verify("not-an-argon2-hash", "password"));
    assertFalse(PasswordHash.verify("$argon2i$v=19$m=65536,t=10,p=1$broken", null));
  }

  @Test
  void affectedChallengeAccountsUseUniqueArgon2Hashes() throws IOException {
    Pattern challengePassword =
        Pattern.compile(
            "^INSERT INTO `BrokenAuthAndSessMangChal(?:Two|Three|Five|Six|Seven)`\\.`users`"
                + ".*VALUES \\(\\d+,\\s*'[^']+',\\s*'(\\$argon2id\\$[^']+)'");
    List<String> hashes = new ArrayList<>();

    for (String line :
        Files.readAllLines(Path.of("src/main/resources/database/moduleSchemas.sql"))) {
      Matcher matcher = challengePassword.matcher(line);
      if (matcher.find()) {
        hashes.add(matcher.group(1));
      }
    }

    assertEquals(85, hashes.size());
    assertEquals(85, new HashSet<>(hashes).size());
  }
}
