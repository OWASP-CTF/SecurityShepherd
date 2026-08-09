/*
 * Client side formatting hint only.
 *
 * This file previously shipped a hard coded 3DES key together with the cipher text of every
 * valid coupon code, which let anyone recover the shop's coupon codes offline. Coupon validity
 * is decided exclusively by the server; the browser only performs a cosmetic format check so the
 * input box can colour itself while the customer types.
 */
function checkCoupon(code) {
  return typeof code === "string" && /^[\x21-\x7E]{4,128}$/.test(code);
}
