// Coupon codes are validated on the server when the order is placed.
//
// This file used to ship a DES implementation, the key and IV it was keyed with, and the whole
// list of coupon codes encrypted under that key, just so the input box could be coloured in. Any
// visitor could read the key out of the script and decrypt the list, which is how the coupon that
// is not advertised on the page was recovered. Nothing secret is sent to the browser any more, so
// the client cannot pre-judge a coupon and there is nothing here to break.
function checkCoupon(couponCode) {
  return true;
}
