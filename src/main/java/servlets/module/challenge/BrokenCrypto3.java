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
 * Bad Crypto Challenge Three. Decrypts user-submitted AES-GCM ciphertext using a key derived from
 * the level secret via SHA-256; authentication failure on tampered/foreign ciphertext prevents the
 * known-plaintext key-recovery attack the previous repeating-key XOR implementation was vulnerable
 * to. <br>
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

  private static final int GCM_IV_LENGTH_BYTES = 12;
  private static final int GCM_TAG_LENGTH_BITS = 128;

  /**
   * Decrypts the supplied value using AES-GCM, with the key derived from the submitted secret via
   * SHA-256. Unlike the repeating-key XOR this replaces, a chosen-ciphertext submission can never
   * reveal information about the key: GCM authenticates the ciphertext, so any value not actually
   * produced by encrypting under the real key fails authentication instead of "decrypting" to
   * something the caller can use to recover key bytes (the XOR version leaked the entire key one
   * byte at a time to anyone who submitted known plaintext, e.g. spaces).
   *
   * @param hash The base64-encoded (IV || ciphertext || GCM tag) to be decrypted
   * @param key The secret the AES key is derived from
   * @return The plain text revealed from the decryption
   * @throws Exception if the input is malformed or fails GCM authentication
   */
  public static String decrypt(String hash, String key) throws Exception {
    byte[] combined = org.apache.commons.codec.binary.Base64.decodeBase64(hash.getBytes("UTF-8"));
    if (combined.length < GCM_IV_LENGTH_BYTES) {
      throw new IllegalArgumentException("Ciphertext too short to contain an IV");
    }
    byte[] iv = java.util.Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH_BYTES);
    byte[] ciphertext =
        java.util.Arrays.copyOfRange(combined, GCM_IV_LENGTH_BYTES, combined.length);

    java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
    javax.crypto.spec.SecretKeySpec keySpec =
        new javax.crypto.spec.SecretKeySpec(sha256.digest(key.getBytes("UTF-8")), "AES");

    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        javax.crypto.Cipher.DECRYPT_MODE,
        keySpec,
        new javax.crypto.spec.GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
    return new String(cipher.doFinal(ciphertext), "UTF-8");
  }
}
