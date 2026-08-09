// The client-side coupon "validity" oracle that used to live in this file has been
// removed: it shipped a hard-coded DES key/IV together with the ciphertext of every
// coupon code (including a secret, non-published one) to the browser, letting anyone
// decrypt them locally with no server interaction. Coupon codes are validated
// server-side against the database, which is the only place that check belongs.
