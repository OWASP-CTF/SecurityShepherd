package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Insecure Cryptographic Storage Challenge Three. <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class BrokenCrypto3 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(BrokenCrypto3.class);
  private static String levelName = "Broken Crypto Challenge 3";
  public static String levelHash =
      "2da053b4afb1530a500120a49a14d422ea56705a7e3fc405a77bc269948ccae1";
  public static String levelResult = "thisisthesecurityshepherdabcencryptionkey";
  private static final int GCM_NONCE_LENGTH = 12;
  private static final int GCM_TAG_LENGTH = 128;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final SecretKey ENCRYPTION_KEY = generateEncryptionKey();

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));

    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      String htmlOutput = new String();

      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);
      try {
        String userData = request.getParameter("userData");
        log.debug("User Submitted - " + userData);

        log.debug("Decrypting user input");
        String decryptedUserData = decrypt(userData);
        log.debug("Decrypted to: " + decryptedUserData);

        htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult")
                + "</h2><p>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult.message")
                + "<br/><br/><em>"
                + Encode.forHtml(decryptedUserData)
                + "</em></p>";
      } catch (Exception e) {
        log.fatal(levelName + " - " + e.toString());
        htmlOutput = errors.getString("error.funky");
      }
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /**
   * Decrypts an authenticated ciphertext produced by {@link #encrypt(String)}.
   *
   * @param hash The cipher text to be decrypted
   * @return The plain text revealed from the decryption
   * @throws GeneralSecurityException If the ciphertext is malformed or fails authentication
   */
  public static String decrypt(String hash) throws GeneralSecurityException {
    byte[] encrypted = Base64.getDecoder().decode(hash);
    if (encrypted.length <= GCM_NONCE_LENGTH) {
      throw new GeneralSecurityException("Ciphertext is too short");
    }

    ByteBuffer input = ByteBuffer.wrap(encrypted);
    byte[] nonce = new byte[GCM_NONCE_LENGTH];
    input.get(nonce);
    byte[] ciphertext = new byte[input.remaining()];
    input.get(ciphertext);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, ENCRYPTION_KEY, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
    return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
  }

  /**
   * Encrypts text for the level's example using authenticated encryption and a fresh nonce.
   *
   * @param plaintext Text to encrypt
   * @return Base64-encoded nonce and authenticated ciphertext
   */
  public static String encrypt(String plaintext) {
    try {
      byte[] nonce = new byte[GCM_NONCE_LENGTH];
      SECURE_RANDOM.nextBytes(nonce);

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, ENCRYPTION_KEY, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
      byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

      return Base64.getEncoder()
          .encodeToString(
              ByteBuffer.allocate(nonce.length + ciphertext.length)
                  .put(nonce)
                  .put(ciphertext)
                  .array());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to encrypt level example", e);
    }
  }

  private static SecretKey generateEncryptionKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(128, SECURE_RANDOM);
      return keyGenerator.generateKey();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }
}
