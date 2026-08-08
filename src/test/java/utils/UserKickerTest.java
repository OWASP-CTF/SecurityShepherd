package utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UserKickerTest {

  @Test
  void kickList_isNullSafeAndDeduplicated() {
    String userName = "user-kicker-test";
    UserKicker.removeFromKicklist(userName);

    UserKicker.addUserToKickList(null);
    UserKicker.addUserToKickList(userName);
    UserKicker.addUserToKickList(userName);

    assertFalse(UserKicker.shouldKickUser(null));
    assertTrue(UserKicker.shouldKickUser(userName));
    UserKicker.removeFromKicklist(userName);
    assertFalse(UserKicker.shouldKickUser(userName));
  }
}
