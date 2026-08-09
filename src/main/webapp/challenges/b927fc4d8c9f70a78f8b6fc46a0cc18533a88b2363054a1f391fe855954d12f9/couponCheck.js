// Coupon codes are validated by the server when the order is placed. This script must never carry
// the encryption key or the encrypted coupon list, so it only checks that something was entered.
function checkCoupon(code) {
	return code != null && code.length > 0;
}
