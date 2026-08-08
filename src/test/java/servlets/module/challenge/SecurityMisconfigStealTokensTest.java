package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SecurityMisconfigStealTokensTest {

  @Test
  void copiedTokenCannotCrossSessionBoundary() {
    assertFalse(SecurityMisconfigStealTokens.isCurrentSessionToken("own-token", "stolen-token"));
  }

  @Test
  void currentSessionsOwnTokenRemainsValid() {
    assertTrue(SecurityMisconfigStealTokens.isCurrentSessionToken("own-token", "own-token"));
  }
}
