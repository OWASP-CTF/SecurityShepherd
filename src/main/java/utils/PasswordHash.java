package utils;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import java.util.Arrays;

/** Central password hashing and verification for challenge-local accounts. */
public final class PasswordHash {

  private static final int ITERATIONS = 10;
  private static final int MEMORY_KIB = 65536;
  private static final int PARALLELISM = 1;
  private static final String DUMMY_HASH =
      "$argon2id$v=19$m=65536,t=10,p=1$uwHteZjs2xHTm5lthjTeeA$"
          + "xOl3qhcJn7c8BUtF1PcB70Fm87lhGOUIVYTPrzch1x0";

  private PasswordHash() {}

  /** Hashes a password with the same Argon2 policy used by Shepherd's primary accounts. */
  public static String hash(String password) {
    if (password == null) {
      throw new IllegalArgumentException("Password is required");
    }

    char[] passwordChars = password.toCharArray();
    try {
      Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
      return argon2.hash(ITERATIONS, MEMORY_KIB, PARALLELISM, passwordChars);
    } finally {
      Arrays.fill(passwordChars, '\0');
    }
  }

  /** Verifies an Argon2 hash without exposing malformed-hash failures to callers. */
  public static boolean verify(String encodedHash, String password) {
    if (password == null) {
      return false;
    }

    boolean hasStoredHash = encodedHash != null && !encodedHash.isEmpty();
    String hashToVerify = hasStoredHash ? encodedHash : DUMMY_HASH;
    char[] passwordChars = password.toCharArray();
    try {
      Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
      return argon2.verify(hashToVerify, passwordChars) && hasStoredHash;
    } catch (RuntimeException e) {
      return false;
    } finally {
      Arrays.fill(passwordChars, '\0');
    }
  }
}
