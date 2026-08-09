// The browser is never given the coupon list, or a key that would reveal it. Only
// the server can tell a valid coupon from an invalid one, and it does so at checkout.
function checkCoupon(code) {
	return true;
}
