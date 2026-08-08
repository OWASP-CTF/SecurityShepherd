package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class BrokenCrypto4Test {

  @Test
  void rejectsFreeOrderDiscountsRecoveredFromClientSideCrypto() {
    assertEquals(0, BrokenCrypto4.validateDiscount(100));
    assertEquals(0, BrokenCrypto4.validateDiscount(-1));
  }

  @Test
  void preservesNormalBoundedDiscounts() {
    assertEquals(25, BrokenCrypto4.validateDiscount(25));
  }
}
