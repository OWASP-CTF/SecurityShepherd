package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Base64;
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
  public static String levelResult = "thisisthesecurityshepherdabcencryptionkey";

  private static final int GCM_NONCE_BYTES = 12;
  private static final int GCM_TAG_BITS = 128;
  private static final SecureRandom secureRandom = new SecureRandom();
  private static final SecretKey encryptionKey = createEncryptionKey();

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
        String decryptedUserData;
        try {
          decryptedUserData = decrypt(userData);
          log.debug("Decrypted to: " + decryptedUserData);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
          // Cipher text that was not produced by this application does not decrypt. Report that
          // as an empty plain text rather than telling the submitter anything about why it
          // failed, which is what turns a decryption endpoint into a padding oracle.
          log.debug("Submitted cipher text could not be decrypted");
          decryptedUserData = new String();
        }

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

  private static SecretKey createEncryptionKey() {
    byte[] keyBytes = new byte[32];
    secureRandom.nextBytes(keyBytes);
    return new SecretKeySpec(keyBytes, "AES");
  }

  /** Returns a fresh example that can still be exercised through the challenge UI. */
  public static String getCiphertextExample() {
    try {
      return encrypt("Security Shepherd keeps this message confidential.");
    } catch (GeneralSecurityException e) {
      log.error("Could not create the crypto challenge example", e);
      return "";
    }
  }

  private static String encrypt(String plainText) throws GeneralSecurityException {
    byte[] nonce = new byte[GCM_NONCE_BYTES];
    secureRandom.nextBytes(nonce);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
    byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    return Base64.encodeBase64String(
        ByteBuffer.allocate(nonce.length + encrypted.length).put(nonce).put(encrypted).array());
  }

  public static String decrypt(String cipherText) throws GeneralSecurityException {
    byte[] encoded = Base64.decodeBase64(cipherText);
    if (encoded.length <= GCM_NONCE_BYTES + (GCM_TAG_BITS / 8)) {
      throw new GeneralSecurityException("Invalid cipher text");
    }

    ByteBuffer input = ByteBuffer.wrap(encoded);
    byte[] nonce = new byte[GCM_NONCE_BYTES];
    input.get(nonce);
    byte[] encrypted = new byte[input.remaining()];
    input.get(encrypted);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
    return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
  }
}
