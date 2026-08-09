// This file previously shipped a full client-side DES implementation together with a
// hard-coded encryption key and a table of pre-computed ciphertexts for every valid coupon
// code ("bits"). Because DES is symmetric and deterministic and both the key and the table
// were exposed to any authenticated browser, an attacker could decrypt the table offline (or
// simply brute force candidate codes against checkCoupon()) to recover every valid
// promotional coupon - including 100%-off codes - without ever touching the server. That is
// the actual "Insecure Cryptographic Storage" flaw this level teaches: secret key material
// and validation data must never be shipped to the client.
//
// checkCoupon() only ever drove a cosmetic green/red hint on the coupon input field - the
// authoritative check has always happened server-side (BrokenCrypto4's doPost looks the
// submitted code up against the coupons table via a parameterized query). Removing the
// client-side oracle does not change server-side behavior or remove any real functionality.
function checkCoupon(code) {
  return true;
}
