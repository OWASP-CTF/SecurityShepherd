package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;

/**
 * Verifies that PoorValidation1 no longer allows a negative order quantity to drive the calculated
 * total to zero/negative and unlock the "free oranges" response, while a legitimate, all-positive
 * order still completes normally.
 */
public class PoorValidation1IT {

  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @BeforeEach
  public void setup() {
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    request.getSession(true).setAttribute("userName", "poorValidationTester");
    request.getSession(true).setAttribute("userRole", "player");
  }

  private String submitOrder(String pineapple, String orange, String apple, String banana)
      throws Exception {
    PoorValidation1 servlet = new PoorValidation1();
    servlet.init(new MockServletConfig("PoorValidation1"));
    request.addParameter("pineappleAmount", pineapple);
    request.addParameter("orangeAmount", orange);
    request.addParameter("appleAmount", apple);
    request.addParameter("bananaAmount", banana);
    servlet.doPost(request, response);
    return response.getContentAsString();
  }

  @Test
  public void testNegativeAmountExploitNoLongerYieldsFreeOranges() {
    try {
      // Previously: -100 pineapples (-3000) + 1 orange (3000) == 0 total, which unlocked the
      // "free oranges" solution key despite never legitimately reaching a zero/negative order.
      String result = submitOrder("-100", "1", "0", "0");
      assertFalse(
          result.contains("Oranges were free"),
          "Negative quantity should no longer unlock the free-oranges response");
      assertTrue(
          result.contains("Order Failed"), "Negative quantity should be rejected as a bad order");
    } catch (Exception e) {
      fail("Could not complete: " + e);
    }
  }

  @Test
  public void testLegitimatePositiveOrderStillSucceeds() {
    try {
      // 1 of each: 30 + 3000 + 45 + 15 = 3090
      String result = submitOrder("1", "1", "1", "1");
      assertTrue(result.contains("Order Complete"), "Legitimate order should still complete");
      assertTrue(result.contains("3090"), "Legitimate order should compute the correct total");
      assertFalse(result.contains("Order Failed"), "Legitimate order should not be treated as bad");
    } catch (Exception e) {
      fail("Could not complete: " + e);
    }
  }
}
