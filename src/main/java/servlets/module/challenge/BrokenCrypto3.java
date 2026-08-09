package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.Arrays;
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
 * Insecure Cryptographic Storage Challenge Three decryption utility <br>
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

  /**
   * Key for this page's decryption utility. It is deliberately NOT the level result: the old code
   * encrypted with the answer itself, so submitting a chosen ciphertext of null bytes returned the
   * key straight back (ASVS 11.2.1 - use a vetted cipher, and never reuse a secret as its own key).
   */
  private static final byte[] DEMO_KEY = {
    (byte) 0x5b, (byte) 0x0a, (byte) 0x2f, (byte) 0x7c,
    (byte) 0x9e, (byte) 0x14, (byte) 0xd3, (byte) 0xa8,
    (byte) 0x6b, (byte) 0x47, (byte) 0xf2, (byte) 0xc0,
    (byte) 0x5d, (byte) 0x81, (byte) 0xe3, (byte) 0x96,
    (byte) 0xa4, (byte) 0xc7, (byte) 0xb2, (byte) 0x1e,
    (byte) 0x8f, (byte) 0x30, (byte) 0xd9, (byte) 0x5c,
    (byte) 0x6a, (byte) 0x1b, (byte) 0x4e, (byte) 0x70,
    (byte) 0x28, (byte) 0xfd, (byte) 0x35, (byte) 0xc9
  };

  private static final int GCM_IV_LENGTH = 12;
  private static final int GCM_TAG_BITS = 128;

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
   * Decrypts the supplied string value using the submitted key
   *
   * @param hash The cipher text to be decrypted
   * @return The plain text revealed from the decryption
   * @throws Exception when the input is not a ciphertext this server produced
   */
  public static String decrypt(String hash) throws Exception {
    byte[] input = org.apache.commons.codec.binary.Base64.decodeBase64(hash.getBytes("UTF-8"));
    if (input.length <= GCM_IV_LENGTH) {
      throw new GeneralSecurityException("Ciphertext too short");
    }
    // AES-GCM authenticates the ciphertext, so a value the server did not produce is rejected
    // outright rather than being "decrypted" into whatever the keystream yields. That is what
    // closes the oracle: a chosen ciphertext no longer reveals anything about the key.
    byte[] iv = Arrays.copyOfRange(input, 0, GCM_IV_LENGTH);
    byte[] ciphertext = Arrays.copyOfRange(input, GCM_IV_LENGTH, input.length);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(DEMO_KEY, "AES"),
        new GCMParameterSpec(GCM_TAG_BITS, iv));
    return new String(cipher.doFinal(ciphertext), "UTF-8");
  }
}
