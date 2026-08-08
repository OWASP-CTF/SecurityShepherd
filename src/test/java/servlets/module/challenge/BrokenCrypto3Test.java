package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class BrokenCrypto3Test {

  @Test
  void chosenPlaintextCannotRecoverTheEncryptionKey() {
    byte[] spaces = new byte[BrokenCrypto3.levelResult.length()];
    java.util.Arrays.fill(spaces, (byte) ' ');
    String craftedCiphertext = Base64.getEncoder().encodeToString(spaces);

    assertThrows(
        Exception.class, () -> BrokenCrypto3.decrypt(craftedCiphertext, BrokenCrypto3.levelResult));
  }

  @Test
  void shippedAuthenticatedCiphertextStillDecrypts() throws Exception {
    String ciphertext =
        "A0rTmfywXXFnfVLzNZtB4UdNc8rQM1zm9KVkWBXYkk0f9GODe0Nqt3tQ1UKQSvoM+n4/"
            + "pdqGsxSF7H6K2sNYCgVz6JYmmTraFXn+S7lEiDTEuvc9YKhDgomBkg==";

    BrokenCrypto3.decrypt(ciphertext, BrokenCrypto3.levelResult).getBytes(StandardCharsets.UTF_8);
  }
}
