package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
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
  public static String levelResult =
      "thisisthesecurityshepherdabcencryptionkey"; // The module's answer. It is kept entirely out
  // of the demo cipher below, so nothing an attacker can do to that cipher discloses it.

  // Key used only to run the little decryption demo on the challenge page. It is unrelated to
  // levelResult by construction, so an attacker who fully recovers it (or forges ciphertext
  // against it) still learns nothing about the module's answer.
  private static final byte[] DEMO_KEY =
      Base64.decodeBase64("lrd1TRm6xWIV6/LTkNy9IhCsqPajtactGI4p0uSN22I=");
  private static final int GCM_IV_BYTES = 12;
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
   * Decrypts the supplied Base64 blob with AES-256/GCM under the fixed demo key.
   *
   * <p>Unlike a bare XOR, GCM is authenticated: any ciphertext that was not produced with the demo
   * key is rejected outright rather than being XOR'd through and handed back to the caller. That
   * closes off the known/chosen-plaintext trick of feeding in bytes of a guessed value (e.g. all
   * spaces) to have the key echoed back byte-by-byte - forged or altered input simply fails
   * authentication here, no matter what bytes it contains.
   *
   * @param userSuppliedCipherText Base64-encoded IV + ciphertext + GCM tag
   * @return The plain text revealed from the decryption
   * @throws Exception if the input is malformed or fails GCM authentication
   */
  public static String decrypt(String userSuppliedCipherText) throws Exception {
    try {
      byte[] blob = Base64.decodeBase64(userSuppliedCipherText.getBytes("UTF-8"));
      if (blob.length <= GCM_IV_BYTES) {
        throw new IllegalArgumentException("Ciphertext too short");
      }
      byte[] iv = new byte[GCM_IV_BYTES];
      byte[] cipherText = new byte[blob.length - GCM_IV_BYTES];
      System.arraycopy(blob, 0, iv, 0, GCM_IV_BYTES);
      System.arraycopy(blob, GCM_IV_BYTES, cipherText, 0, cipherText.length);

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(DEMO_KEY, "AES"),
          new GCMParameterSpec(GCM_TAG_BITS, iv));
      byte[] plainText = cipher.doFinal(cipherText); // throws on any tampering/forgery
      return new String(plainText, "UTF-8");
    } catch (UnsupportedEncodingException ex) {
      throw new IllegalStateException(ex);
    }
  }
}
