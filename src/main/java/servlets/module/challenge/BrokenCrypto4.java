package servlets.module.challenge;

import dbProcs.Database;
import dbProcs.Getter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Level : Broken Crypto 4 <br>
 * <br>
 *
 * <p>This file is part of the Security Shepherd Project.
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
public class BrokenCrypto4 extends HttpServlet {

  private static final String levelName = new String("Broken Crypto 4");
  private static final String levelHash =
      new String("b927fc4d8c9f70a78f8b6fc46a0cc18533a88b2363054a1f391fe855954d12f9");
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(BrokenCrypto4.class);

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from
    // proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);

      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      String applicationRoot = getServletContext().getRealPath("");
      try {
        // Get and validate cart amounts
        int pineappleAmount =
            validateAmount(Integer.parseInt(request.getParameter("pineappleAmount")));
        log.debug("pineappleAmount - " + pineappleAmount);
        int orangeAmount = validateAmount(Integer.parseInt(request.getParameter("orangeAmount")));
        log.debug("orangeAmount - " + orangeAmount);
        int appleAmount = validateAmount(Integer.parseInt(request.getParameter("appleAmount")));
        log.debug("appleAmount - " + appleAmount);
        int bananaAmount = validateAmount(Integer.parseInt(request.getParameter("bananaAmount")));
        log.debug("bananaAmount - " + bananaAmount);
        String couponCode = request.getParameter("couponCode");
        log.debug("couponCode - " + couponCode);

        // Working out costs
        int pineappleCost = pineappleAmount * 30;
        int orangeCost = orangeAmount * 3000;
        int appleCost = appleAmount * 45;
        int bananaCost = bananaAmount * 15;
        int perCentOffPineapple = 0; // Will search for coupons in DB and update this int
        int perCentOffOrange = 0; // Will search for coupons in DB and update this int
        int perCentOffApple = 0; // Will search for coupons in DB and update this int
        int perCentOffBanana = 0; // Will search for coupons in DB and update this int

        htmlOutput = new String();
        Connection conn = Database.getChallengeConnection(applicationRoot, "CryptoChallengeShop");
        log.debug("Looking for Coupons");
        // A coupon code is a bearer secret: whoever holds it gets the discount, so it is stored
        // the way a credential is stored rather than the way a lookup key is. Each row carries
        // its own salt, so two shops issuing the same code do not store the same value and a
        // table of precomputed digests is worth nothing, and the digest is deliberately slow so
        // that walking a list of likely codes costs real time. That means the code cannot be
        // used as an index, so the small coupon table is read and each row compared in turn.
        PreparedStatement prepstmt =
            conn.prepareStatement("SELECT itemId, perCentOff, couponCode FROM coupons");
        ResultSet coupons = prepstmt.executeQuery();
        try {
          boolean couponFound = false;
          while (!couponFound && coupons.next()) {
            if (!couponMatches(coupons.getString(3), couponCode)) {
              continue;
            }
            couponFound = true;
            int validatedDiscount = validateDiscount(coupons.getInt(2));
            if (coupons.getInt(1) == 1) // Pineapple
            {
              log.debug("Found coupon for %" + validatedDiscount + " off Pineapple");
              perCentOffPineapple = validatedDiscount;
            } else if (coupons.getInt(1) == 2) // Orange
            {
              log.debug("Found coupon for %" + validatedDiscount + " off Orange");
              perCentOffOrange = validatedDiscount;
            } else if (coupons.getInt(1) == 3) // Apple
            {
              log.debug("Found coupon for %" + validatedDiscount + " off Apple");
              perCentOffApple = validatedDiscount;
            } else if (coupons.getInt(1) == 4) // Banana
            {
              log.debug("Found coupon for %" + validatedDiscount + " off Banana");
              perCentOffBanana = validatedDiscount;
            }
          }
          if (!couponFound) {
            log.debug("Invalid Coupon Code");
          }
        } catch (Exception e) {
          log.debug("Could Not Find Coupon: " + e.toString());
        }
        conn.close();

        // Work Out Final Cost
        pineappleCost = pineappleCost - ((pineappleCost * perCentOffPineapple) / 100);
        appleCost = appleCost - ((appleCost * perCentOffApple) / 100);
        bananaCost = bananaCost - ((bananaCost * perCentOffBanana) / 100);
        orangeCost = orangeCost - ((orangeCost * perCentOffOrange) / 100);
        int finalCost = pineappleCost + appleCost + bananaCost + orangeCost;

        // Output Order
        htmlOutput =
            "<h3>"
                + bundle.getString("insecureCryptoStorage.4.orderComplete")
                + "</h3>"
                + "<p>"
                + bundle.getString("insecureCryptoStorage.4.orderShipped")
                + "<br/></p>"
                + "<p>"
                + bundle.getString("insecureCryptoStorage.4.totalCost")
                + " <a><strong>$"
                + finalCost
                + "</strong></a></p>";
        if (orangeAmount > 0 && orangeCost == 0) {
          htmlOutput +=
              "<p>"
                  + bundle.getString("insecureCryptoStorage.4.freeOranges")
                  + " - "
                  + Hash.generateUserSolution(
                      Getter.getModuleResultFromHash(
                          getServletContext().getRealPath(""), levelHash),
                      (String) ses.getAttribute("userName"))
                  + "</p>";
        }

      } catch (Exception e) {
        log.debug("Didn't complete order: " + e.toString());
        htmlOutput += "<p>" + bundle.getString("insecureCryptoStorage.4.orderFailed") + "</p>";
      }
      try {
        Thread.sleep(1000);
      } catch (Exception e) {
        log.error("Failed to Pause: " + e.toString());
      }
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /** Largest quantity of any single item one order may contain. */
  private static final int maxItemAmount = 1000;

  /** Iterations behind each stored coupon code digest. */
  private static final int couponHashIterations = 100000;

  /**
   * Confines a submitted quantity to a sane range. A quantity outside it is a mistake in the form
   * rather than an order, so it is brought back into range instead of failing the whole request.
   *
   * @param amount Quantity as submitted by the client
   * @return The quantity confined to 0..maxItemAmount
   */
  private static int validateAmount(int amount) {
    if (amount < 0) {
      return 0;
    }
    if (amount > maxItemAmount) {
      return maxItemAmount;
    }
    return amount;
  }

  private static int validateDiscount(int discount) {
    if (discount < 0 || discount > 90) {
      throw new IllegalArgumentException("Coupon discount is outside the allowed range");
    }
    return discount;
  }

  /**
   * Reports whether a submitted coupon code is the one a stored row was issued for.
   *
   * @param storedCode The stored value, as a hex salt and hex digest separated by a dollar sign
   * @param submittedCode The code as submitted by the shopper
   * @return True when the submitted code produces the stored digest under the stored salt
   */
  private static boolean couponMatches(String storedCode, String submittedCode) {
    if (storedCode == null || submittedCode == null) {
      return false;
    }
    int separator = storedCode.indexOf('$');
    if (separator < 1 || separator == storedCode.length() - 1) {
      log.error("A coupon row is not stored as a salt and a digest and cannot be matched");
      return false;
    }
    try {
      byte[] salt = Hex.decodeHex(storedCode.substring(0, separator).toCharArray());
      byte[] expected = Hex.decodeHex(storedCode.substring(separator + 1).toCharArray());
      // Compared in constant time: an early exit on the first differing byte tells a caller how
      // much of a guess was right, which is enough to build the rest of the code a byte at a time.
      return MessageDigest.isEqual(expected, couponDigest(submittedCode, salt, expected.length));
    } catch (Exception e) {
      log.error("Could not compare a submitted coupon code: " + e.toString());
      return false;
    }
  }

  private static byte[] couponDigest(String couponCode, byte[] salt, int lengthInBytes)
      throws GeneralSecurityException {
    PBEKeySpec spec =
        new PBEKeySpec(couponCode.toCharArray(), salt, couponHashIterations, lengthInBytes * 8);
    try {
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    } finally {
      spec.clearPassword();
    }
  }
}
