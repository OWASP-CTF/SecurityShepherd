package servlets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

class MobileLoginTest {

  @Test
  void authenticationResponse_doesNotExposeSessionIdentifier() {
    JSONObject response = MobileLogin.authenticationResponse("csrf-token");

    assertEquals("csrf-token", response.getString("token"));
    assertFalse(response.has("JSESSIONID"));
  }
}
