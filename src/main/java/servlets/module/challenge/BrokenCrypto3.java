package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
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
 * Bad Crypto Challenge Three Really bad crypto algorithm to break. Will reveal key if spaces are
 * submitted <br>
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
  public static String levelResult =
      "thisisthesecurityshepherdabcencryptionkey"; // Is used as encryption key in this level

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
        // Using level key as encryption key
        String decryptedUserData = decrypt(userData, levelResult);
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
   * Decrypts the supplied string value using the submitted key.
   *
   * <p>Previously this used a hand-rolled repeating-key XOR "cipher" with no integrity check: any
   * attacker-chosen ciphertext was happily decrypted with the server's secret key, so submitting a
   * known plaintext (e.g. a run of space characters) let an attacker recover the key byte-by-byte
   * from the output (a classic known-plaintext attack against XOR keystream reuse). Authenticated
   * AES-GCM decryption closes this: tampered/foreign ciphertext fails the authentication tag check
   * and throws instead of silently returning attacker-controlled keystream material, so the key can
   * no longer be recovered via this oracle.
   *
   * @param hash The cipher text to be decrypted (base64 of a 12-byte GCM nonce followed by the
   *     GCM-encrypted payload and authentication tag)
   * @param key The encryption key (hashed with SHA-256 to derive a proper 256-bit AES key)
   * @return The plain text revealed from the decryption
   * @throws Exception Thrown if the ciphertext is malformed or fails authentication
   */
  public static String decrypt(String hash, String key) throws Exception {
    byte[] combined = org.apache.commons.codec.binary.Base64.decodeBase64(hash.getBytes("UTF-8"));
    int ivLength = 12;
    if (combined.length < ivLength + 1) {
      throw new IllegalArgumentException("Ciphertext too short");
    }
    byte[] iv = java.util.Arrays.copyOfRange(combined, 0, ivLength);
    byte[] cipherText = java.util.Arrays.copyOfRange(combined, ivLength, combined.length);

    javax.crypto.spec.SecretKeySpec keySpec = deriveKey(key);
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec);
    byte[] plain = cipher.doFinal(cipherText);
    return new String(plain, "UTF-8");
  }

  /**
   * Derives a 256-bit AES key from an arbitrary-length key string via SHA-256.
   *
   * @param key Source key material
   * @return A SecretKeySpec suitable for AES-256
   * @throws Exception Thrown if SHA-256 is unavailable
   */
  private static javax.crypto.spec.SecretKeySpec deriveKey(String key) throws Exception {
    java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
    byte[] keyBytes = sha256.digest(key.getBytes("UTF-8"));
    return new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
  }
}
