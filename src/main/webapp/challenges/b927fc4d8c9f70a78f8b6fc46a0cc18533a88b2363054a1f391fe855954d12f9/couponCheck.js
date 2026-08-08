// Coupon codes are authoritative server-side only (see the shop's order servlet, which looks
// the submitted code up in the coupons table via a parameterised query). This file previously
// mirrored that check client-side using a fixed-key, reversible DES routine, which let anyone
// who fetched this file decrypt the embedded ciphertext list and recover every coupon code -
// including ones never advertised on the page - without ever contacting the server or the
// database. That reversible, fixed-key scheme has been removed; this file no longer carries or
// derives any coupon secret. Submitting a code still gives an authoritative answer from the
// server when the form is submitted.
function checkCoupon(code) {
  return typeof code === "string" && code.length > 0;
}
