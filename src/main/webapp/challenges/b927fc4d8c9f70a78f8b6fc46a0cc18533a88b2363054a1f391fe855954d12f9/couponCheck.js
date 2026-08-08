// Coupon codes are authoritatively validated by the server when an order is submitted.
// No coupon list, encryption key, or other secret is shipped to the browser.
function checkCoupon(couponCode) {
  return typeof couponCode === "string";
}
