package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
        log.debug("Ciphertext submitted for decryption");

        log.debug("Decrypting user input");
        // Using level key as encryption key
        String decryptedUserData = decrypt(userData, levelResult);
        log.debug("Ciphertext decrypted successfully");

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
   * Decrypts the supplied string value using the submitted key. Uses AES/GCM so the ciphertext is
   * authenticated: tampered or attacker-crafted input fails the tag check instead of quietly
   * decrypting to key-derived material.
   *
   * @param hash The cipher text to be decrypted
   * @param key The encryption key
   * @return The plain text revealed from the decryption
   * @throws Exception Throws illegal state Exception
   */
  public static String decrypt(String hash, String key) throws Exception {
    try {
      byte[] cipherText = org.apache.commons.codec.binary.Base64.decodeBase64(hash.getBytes());
      SecretKeySpec skeySpec = new SecretKeySpec(deriveKeyMaterial(key), "AES");
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, skeySpec, new GCMParameterSpec(128, deriveIv(key)));
      return new String(cipher.doFinal(cipherText), "UTF-8");
    } catch (java.io.UnsupportedEncodingException ex) {
      throw new IllegalStateException(ex);
    }
  }

  /**
   * Derives 256 bits of AES key material from the level key so the raw level key is never used
   * directly as cipher key bytes.
   *
   * @param key The encryption key
   * @return 32 bytes of key material
   */
  private static byte[] deriveKeyMaterial(String key) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(key.getBytes("UTF-8"));
  }

  /**
   * Derives a 96 bit GCM nonce from the level key
   *
   * @param key The encryption key
   * @return 12 bytes to use as the GCM IV
   */
  private static byte[] deriveIv(String key) throws Exception {
    byte[] iv = new byte[12];
    System.arraycopy(deriveKeyMaterial(key), 0, iv, 0, iv.length);
    return iv;
  }
}
