package servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ACSTest {

  @Test
  void firstAttribute_rejectsMissingAndEmptyClaims() {
    Map<String, List<String>> attributes =
        Collections.singletonMap("username", Collections.singletonList("alice"));

    assertEquals("alice", ACS.firstAttribute(attributes, "username"));
    assertNull(ACS.firstAttribute(attributes, "missing"));
    assertNull(ACS.firstAttribute(attributes, null));
    assertNull(ACS.firstAttribute(null, "username"));
    assertNull(
        ACS.firstAttribute(
            Collections.singletonMap("username", Collections.emptyList()), "username"));
  }
}
