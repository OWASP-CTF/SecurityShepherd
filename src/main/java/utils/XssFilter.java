package utils;

import java.net.MalformedURLException;
import java.net.URL;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;

/**
 * Provides a number of filters that are used in different XSS challenges. <br>
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
public class XssFilter {

  private static final Logger log = LogManager.getLogger(XssFilter.class);

  private static final String FALLBACK_URL =
      "https://www.google.com/search?q=What+does+a+HTTP+link+look+like";

  /**
   * Validates a URL for use in an href attribute.
   *
   * @param input URL to validate
   * @return An http(s) URL encoded for an HTML attribute, or a fallback URL
   */
  public static String anotherBadUrlValidate(String input) {
    return validateHttpUrl(input);
  }

  /**
   * Validates a URL for use in an href attribute.
   *
   * @param input URL to validate
   * @return An http(s) URL encoded for an HTML attribute, or a fallback URL
   */
  public static String badUrlValidate(String input) {
    return validateHttpUrl(input);
  }

  /**
   * Parses the input as a URL and admits only the http and https schemes, then encodes the result
   * for the attribute context it is written into. Blacklisting characters could not work here:
   * anything that survives the filter still lands unencoded inside href="...".
   *
   * @param input URL to validate
   * @return An encoded http(s) URL, or an encoded fallback URL when input is not one
   */
  private static String validateHttpUrl(String input) {
    if (input == null) {
      return Encode.forHtmlAttribute(FALLBACK_URL);
    }
    try {
      URL theUrl = new URL(input.trim());
      String protocol = theUrl.getProtocol();
      if (!"http".equals(protocol) && !"https".equals(protocol)) {
        log.debug("Rejected URL with non-HTTP(S) scheme: " + protocol);
        return Encode.forHtmlAttribute(FALLBACK_URL);
      }
      return Encode.forHtmlAttribute(theUrl.toString());
    } catch (MalformedURLException e) {
      log.debug("Could not cast URL from input: " + e.toString());
      return Encode.forHtmlAttribute(FALLBACK_URL);
    }
  }

  /**
   * Encodes input for the HTML body and attribute contexts it is written into.
   *
   * @param input String to be encoded
   * @return HTML-encoded input
   */
  public static String encodeForHtml(String input) {
    log.debug("Encoding input for HTML");
    return Encode.forHtml(input);
  }

  /**
   * Encodes input for the HTML body context it is written into.
   *
   * @param input String to be encoded
   * @return HTML-encoded input
   */
  public static String levelFour(String input) {
    log.debug("Encoding input at XSS levelFour");
    return Encode.forHtml(input);
  }

  /**
   * Encodes input for the HTML body context it is written into.
   *
   * @param input String to be encoded
   * @return HTML-encoded input
   */
  public static String levelOne(String input) {
    log.debug("Encoding input at XSS levelOne");
    return Encode.forHtml(input);
  }

  /**
   * Encodes input for the HTML body context it is written into.
   *
   * @param input String to be encoded
   * @return HTML-encoded input
   */
  public static String levelThree(String input) {
    log.debug("Encoding input at XSS levelThree");
    return Encode.forHtml(input);
  }

  /**
   * Encodes input for the HTML body context it is written into.
   *
   * @param input String to be encoded
   * @return HTML-encoded input
   */
  public static String levelTwo(String input) {
    log.debug("Encoding input at XSS levelTwo");
    return Encode.forHtml(input);
  }
}
