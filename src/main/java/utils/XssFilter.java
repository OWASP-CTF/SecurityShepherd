package utils;

import java.net.URI;
import java.net.URISyntaxException;
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

  /**
   * Confines a user supplied link to an absolute http(s) URL.
   *
   * <p>Only the http and https schemes are allowed through, so values that would turn an href into
   * a script sink (javascript:, data:, vbscript:, protocol relative links) are rejected outright
   * rather than filtered. Anything that is not a well formed absolute http(s) URL is replaced with
   * a harmless placeholder link. Callers must still encode the result for the context it is written
   * into.
   *
   * @param input URL to validate
   * @return The submitted URL when it is an absolute http(s) URL, otherwise a placeholder link
   */
  public static String safeHttpUrl(String input) {
    final String howToMakeAUrlUrl =
        "https://www.google.com/search?q=What+does+a+HTTP+link+look+like";
    if (input == null) {
      return howToMakeAUrlUrl;
    }
    try {
      URI theUri = new URI(input.trim());
      String scheme = theUri.getScheme();
      if (theUri.isAbsolute()
          && scheme != null
          && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
          && theUri.getHost() != null) {
        return theUri.toASCIIString();
      }
      log.debug("Rejected link that was not an absolute http(s) URL");
    } catch (URISyntaxException e) {
      log.debug("Could not parse URL from input: " + e.toString());
    }
    return howToMakeAUrlUrl;
  }

  /**
   * A method to badly validate a URL
   *
   * @param input URL to validate
   * @return A poorly validated URL (XSS RISK)
   */
  public static String anotherBadUrlValidate(String input) {
    return Encode.forHtmlAttribute(safeHttpUrl(input));
  }

  /**
   * White lists for specific URL types but doesn't sanitise it well
   *
   * @param input
   * @return
   */
  public static String badUrlValidate(String input) {
    return Encode.forHtmlAttribute(safeHttpUrl(input));
  }

  /**
   * Encodes for HTML, but doesn't escape ampersands
   *
   * @param input
   * @return
   */
  public static String encodeForHtml(String input) {
    log.debug("Encoding untrusted HTML text");
    return Encode.forHtml(input == null ? "" : input);
  }

  /**
   * Filters for specific javascript events recursively in a specific order. Can be bypassed by
   * embedding a trigger late in the list in a trigger early in the list
   *
   * @param input String to be filtered for XSS attacks
   * @return XSS Blacklist filtered HTML
   */
  public static String levelFour(String input) {
    return encodeForHtml(input);
  }

  /**
   * Filters the word "script" specifically
   *
   * @param input Input to be filtered for XSS
   * @return XSS Blacklist filtered HTML
   */
  public static String levelOne(String input) {
    return encodeForHtml(input);
  }

  /**
   * Filters for javascript triggers twice before stopping and breaks HTML encodings
   *
   * @param input
   * @return
   */
  public static String levelThree(String input) {
    return encodeForHtml(input);
  }

  /**
   * Filters specific javascript event triggers
   *
   * @param input String to be filtered for XSS attacks
   * @return XSS Blacklist filtered HTML
   */
  public static String levelTwo(String input) {
    return encodeForHtml(input);
  }

  /**
   * Use this to cripple HTML encoded attacks. This is can be used to limit the vectors of attack
   * for success
   *
   * @param input The string you want to remove HTML encoding from
   * @return A string without HTML encoding
   */
  private static String screwHtmlEncodings(String input) {
    input = input.replaceAll("&", "!").replaceAll(":", "!");
    return input;
  }
}
