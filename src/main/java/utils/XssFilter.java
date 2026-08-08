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

  private static final String SAFE_URL =
      "https://www.google.com/search?q=What+does+a+HTTP+link+look+like";

  /**
   * Validates that the submitted value is an http(s) URL and encodes it for safe use inside an HTML
   * attribute.
   *
   * @param input URL to validate
   * @return An encoded, scheme restricted URL
   */
  public static String anotherBadUrlValidate(String input) {
    return safeUrl(input);
  }

  /**
   * Validates that the submitted value is an http(s) URL and encodes it for safe use inside an HTML
   * attribute.
   *
   * @param input URL to validate
   * @return An encoded, scheme restricted URL
   */
  public static String badUrlValidate(String input) {
    return safeUrl(input);
  }

  /**
   * Encodes the supplied value for safe inclusion in HTML.
   *
   * @param input untrusted input
   * @return HTML encoded output
   */
  public static String encodeForHtml(String input) {
    if (input == null) {
      return "";
    }
    return Encode.forHtml(input);
  }

  /**
   * Encodes the supplied value for safe inclusion in HTML.
   *
   * @param input String to be encoded
   * @return HTML encoded output
   */
  public static String levelFour(String input) {
    return encodeForHtml(input);
  }

  /**
   * Encodes the supplied value for safe inclusion in HTML.
   *
   * @param input String to be encoded
   * @return HTML encoded output
   */
  public static String levelOne(String input) {
    return encodeForHtml(input);
  }

  /**
   * Encodes the supplied value for safe inclusion in HTML.
   *
   * @param input String to be encoded
   * @return HTML encoded output
   */
  public static String levelThree(String input) {
    return encodeForHtml(input);
  }

  /**
   * Encodes the supplied value for safe inclusion in HTML.
   *
   * @param input String to be encoded
   * @return HTML encoded output
   */
  public static String levelTwo(String input) {
    return encodeForHtml(input);
  }

  /**
   * Restricts a submitted URL to the http and https schemes and encodes it for use inside a quoted
   * HTML attribute. Anything else is replaced with a safe default link.
   *
   * @param input untrusted URL
   * @return an encoded, scheme restricted URL
   */
  private static String safeUrl(String input) {
    String candidate = SAFE_URL;
    if (input != null) {
      try {
        URL theUrl = new URL(input.trim());
        String protocol = theUrl.getProtocol();
        if ("http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol)) {
          candidate = theUrl.toString();
        } else {
          log.debug("Rejected URL scheme: " + protocol);
        }
      } catch (MalformedURLException e) {
        log.debug("Could not cast URL from input: " + e.toString());
      }
    }
    return Encode.forHtmlAttribute(candidate);
  }
}
