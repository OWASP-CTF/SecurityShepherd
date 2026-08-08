package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class BrokenCrypto3Test {

  private static final String LEGACY_PUBLIC_KEY = "thisisthesecurityshepherdabcencryptionkey";

  @Test
  void chosenPlaintextCannotRecoverTheEncryptionKey() {
    byte[] spaces = new byte[LEGACY_PUBLIC_KEY.length()];
    java.util.Arrays.fill(spaces, (byte) ' ');
    String craftedCiphertext = Base64.getEncoder().encodeToString(spaces);

    assertThrows(Exception.class, () -> BrokenCrypto3.decrypt(craftedCiphertext));
  }

  @Test
  void runtimeAuthenticatedCiphertextStillDecrypts() throws Exception {
    String ciphertext = BrokenCrypto3.sampleCiphertext();

    assertEquals("This crypto is not strong", BrokenCrypto3.decrypt(ciphertext));
  }

  @Test
  void encryptingTheSamePlaintextUsesFreshNonces() throws Exception {
    String first = BrokenCrypto3.encrypt("same plaintext");
    String second = BrokenCrypto3.encrypt("same plaintext");

    assertNotEquals(first, second);
    assertEquals("same plaintext", BrokenCrypto3.decrypt(first));
    assertEquals("same plaintext", BrokenCrypto3.decrypt(second));
  }

  @Test
  void sourceVisibleChallengeKeyCannotForgeAcceptedCiphertext() throws Exception {
    String forgedCiphertext = encryptWithPublishedKey("attacker-controlled plaintext");

    assertThrows(Exception.class, () -> BrokenCrypto3.decrypt(forgedCiphertext));
  }

  private static String encryptWithPublishedKey(String plaintext) throws Exception {
    byte[] keyMaterial =
        MessageDigest.getInstance("SHA-256")
            .digest(LEGACY_PUBLIC_KEY.getBytes(StandardCharsets.UTF_8));
    byte[] nonce = new byte[12];
    java.util.Arrays.fill(nonce, (byte) 7);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(keyMaterial, "AES"),
        new GCMParameterSpec(128, nonce));
    byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    byte[] envelope = new byte[nonce.length + cipherText.length];
    System.arraycopy(nonce, 0, envelope, 0, nonce.length);
    System.arraycopy(cipherText, 0, envelope, nonce.length, cipherText.length);
    return Base64.getEncoder().encodeToString(envelope);
  }
}
