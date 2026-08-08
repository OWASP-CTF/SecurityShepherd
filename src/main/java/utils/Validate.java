package utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class is used to validate various inputs <br>
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
public class Validate {

  private static final Logger log = LogManager.getLogger(Validate.class);

  /**
   * Finds JSession token from user's cookies[], validates and returns.
   *
   * @param userCookies Cookies from users browser
   * @return JSession Id
   */
  public static Cookie getSessionId(Cookie[] userCookies) {
    if (userCookies == null) {
      return null;
    }

    for (Cookie userCookie : userCookies) {
      if (userCookie != null && "JSESSIONID".equals(userCookie.getName())) {
        return userCookie;
      }
    }
    return null;
  }

  /**
   * Finds CSRF token from user's cookies[], validates.
   *
   * @param userCookies All of the user's cookies from their browser
   * @return csrfCookie
   */
  public static Cookie getToken(Cookie[] userCookies) {
    if (userCookies == null) {
      return null;
    }

    Cookie theToken = null;
    for (Cookie userCookie : userCookies) {
      if (userCookie != null && "token".equals(userCookie.getName())) {
        theToken = userCookie;
        break; // End Loop, because we found the token
      }
    }
    if (theToken != null) {
      // log.debug("Found Cookie " + theToken.getName() + " with value " +
      // theToken.getValue());
      // The Token is currently designed to be a random Big Integer. If the Big
      // Integer Case does not work, the token has been modified. Potentially in a
      // malicious manner
      try {
        BigInteger theTokenCasted = new BigInteger(theToken.getValue());
        BigInteger tenGrand = new BigInteger("10000");
        BigInteger tenGrandNeg = new BigInteger("-10000");
        if (!(theTokenCasted.compareTo(tenGrand) > 0
            || theTokenCasted.compareTo(tenGrandNeg) < 0)) {
          log.error("CSRF Cookie Token was modified in some manor!");
          theToken = null;
        }
      } catch (Exception e) {
        log.error("CSRF Cookie Token was modified in some manor: " + e.toString());
        theToken = null;
      }
    }
    return theToken;
  }

  /**
   * Validates class year when creating classes. Class year should be YY/YY, e.g. 11/12. So the
   * first year must be less than the second.
   *
   * @param classYear Class Year in YY/YY format, e.g. 11/12.
   * @return Boolean value stating weather or not these supplied attributes make a valid class year
   */
  public static boolean isValidClassYear(String classYear) {
    if (classYear == null || !classYear.matches("[0-9]{4}")) {
      return false;
    }
    return Integer.parseInt(classYear) > 2010;
  }

  /**
   * Email validation
   *
   * @param email
   * @return Boolean reflect email validity
   */
  public static boolean isValidEmailAddress(String email) {
    if (email == null || email.isEmpty() || containsControlCharacter(email)) {
      return false;
    }
    try {
      InternetAddress emailAddr = new InternetAddress(email);
      emailAddr.validate();
      return true;
    } catch (AddressException ex) {
      return false;
    }
  }

  /**
   * Invalid password detecter
   *
   * @param passWord
   * @return
   */
  public static boolean isValidPassword(String passWord) {
    boolean result = passWord != null && passWord.length() > 7 && passWord.length() <= 512;
    if (!result) {
      log.debug("Invalid Password detected");
    }
    return result;
  }

  /**
   * Used to validate user creation requests
   *
   * @param userName User Name
   * @param passWord User Password
   * @return Boolean value stating weather or not these supplied attributes make a valid user
   */
  public static boolean isValidUser(String userName, String passWord) {
    boolean userOK = isValidUserName(userName);
    boolean passOK = isValidPassword(passWord);

    boolean result = userOK && passOK;

    if (!result) {
      log.debug("Invalid Data detected in Validate.isValidUser()");
    }
    return result;
  }

  /**
   * Used to validate user creation requests
   *
   * @param userName User Name
   * @param passWord User Password
   * @param userAddress User address
   * @return Boolean value stating weather or not these supplied attributes make a valid user
   */
  public static boolean isValidUser(String userName, String passWord, String userAddress) {
    boolean result =
        isValidUserName(userName)
            && isValidPassword(passWord)
            && userAddress != null
            && userAddress.length() <= 128
            && !containsControlCharacter(userAddress);
    if (!result) {
      log.debug("Invalid Data detected in Validate.isValidUser()");
    }
    return result;
  }

  private static boolean isValidUserName(String userName) {
    return userName != null && userName.matches("[A-Za-z0-9._-]{3,32}");
  }

  private static boolean containsControlCharacter(String value) {
    return value.codePoints().anyMatch(Character::isISOControl);
  }

  /**
   * Quick method to prevent data and javascript URLs
   *
   * @param theUrl
   * @return
   */
  public static String makeValidUrl(String theUrl) {
    theUrl = theUrl.toLowerCase();
    if (!theUrl.startsWith("http")) {
      theUrl = "http" + theUrl;
      log.debug("Transformed to: " + theUrl);
    }
    return theUrl;
  }

  /**
   * Session is checked for credentials and ensures that they have not been modified and that they
   * are valid for an administrator
   *
   * @param ses HttpSession from users browser
   * @return Boolean value that reflects the validity of the admins session
   */
  public static boolean validateAdminSession(HttpSession ses) {
    boolean result = false;
    String userName = new String();
    if (ses == null) {
      log.debug("No Session Found");
    } else {
      if (ses.getAttribute("logout") != null) {
        log.debug("Logout Attribute Found: Invalidating session...");
        ses.invalidate(); // make servlet engine forget the session
      } else {
        // log.debug("Active Session Found");
        if (ses.getAttribute("userRole") != null && ses.getAttribute("userName") != null) {
          try {
            userName = (String) ses.getAttribute("userName");
            // log.debug("Session holder is " + userName);
            String role = (String) ses.getAttribute("userRole");
            result = role.equals("admin");
            if (!result) {
              log.fatal(
                  "User " + userName + " Attempting Admin functions! (CSRF Tokens Not Checked)");
            }
          } catch (Exception e) {
            log.fatal("Tampered Parameter Detected!!! Could not parameters");
          }
        } else {
          log.debug("Session has no credentials");
        }
      }
    }
    return result;
  }

  /**
   * Session is checked for credentials and ensures that they have not been modified and that they
   * are valid for an administrator. This function also validates CSRF tokens
   *
   * @param ses HttpSession from users browser
   * @return Boolean value that reflects the validity of the admins session
   */
  public static boolean validateAdminSession(
      HttpSession ses, Cookie cookieToken, Object requestToken) {
    boolean result = false;
    String userName = new String();
    if (ses == null) {
      log.debug("No Session Found");
    } else {
      if (ses.getAttribute("logout") != null) {
        log.debug("Logout Attribute Found: Invalidating session...");
        ses.invalidate(); // make servlet engine forget the session
      } else {
        // log.debug("Active Session Found");
        if (ses.getAttribute("userRole") != null && ses.getAttribute("userName") != null) {
          try {
            userName = (String) ses.getAttribute("userName");
            // log.debug("Session holder is " + userName);
            String role = (String) ses.getAttribute("userRole");
            result = role.equals("admin") && validateTokens(ses, cookieToken, requestToken);
            if (!result) {
              // Check CSRF Tokens of User to ensure they are not being CSRF'd into causing
              // Unauthorised Access Alert
              boolean validCsrfTokens = validateTokens(ses, cookieToken, requestToken);
              if (validCsrfTokens) {
                log.fatal(
                    "User account "
                        + userName
                        + " Attempting Admin functions! (With Valid CSRF Tokens)");
              } else {
                log.error(
                    "User account " + userName + " accessing admin function with bad CSRF Tokens");
              }
            }

          } catch (Exception e) {
            log.fatal("Tampered Parameter Detected!!! Could not parameters");
          }
        } else {
          log.debug("Session has no credentials");
        }
      }
    }
    return result;
  }

  /**
   * Takes a String submitted to be used to encrypt and makes it the correct length for an
   * encryption key
   *
   * @param userSalt String to be validated
   * @return A Valid Encryption Key based on the input
   */
  public static String validateEncryptionKey(String userSalt) {
    String newKey = new String();
    int keySize = userSalt.length();
    if (keySize == 16) {
      // log.debug("Key Already Valid");
      newKey = userSalt;
    } else {
      if (keySize > 16) {
        // log.debug("Key too Long...");
        newKey = userSalt.substring(0, 16);
      } else // Shorter than 16
      {
        // log.debug("Key too Short...");
        newKey = userSalt;
        int howManyTimes = (16 / keySize) - 1;
        // log.debug("Repeating String " + howManyTimes + " times");
        for (int i = 0; i < howManyTimes; i++) {
          newKey += userSalt;
        }
        keySize = newKey.length();
        int toAdd = 16 - keySize;
        // log.debug("Adding " + toAdd + " more characters");
        newKey = newKey.concat(userSalt.substring(0, toAdd));
      }
    }
    log.debug("Encryption key is '" + newKey + "'");
    return newKey;
  }

  /**
   * Function that will check if a valid language is set. if not, returns en (English)
   *
   * @param ses Session Language Parameter
   * @return en by default, or the valid setting found in the submitted lang
   */
  public static String validateLanguage(HttpSession ses) {
    String result = "en_GB";
    String lang = new String();

    try {
      lang = ses.getAttribute("lang").toString();
    } catch (NullPointerException e) {
      lang = "";
    }
    // log.debug("lang submitted: " + lang);
    if (lang != null) {
      if (lang.matches(".[a-z]{2}-[A-Z]{2}$")) {
        result = lang;
      }
    }
    // log.debug("lang set to: " + result);

    return result;
  }

  /**
   * Validates objects received through a function request. Also ensures max length is not too high.
   *
   * @param input Object to validate
   * @param maxLength Maximum length of object
   * @return Validated String value or empty string value
   */
  public static String validateParameter(Object input, int maxLength) {
    if (!(input instanceof String) || maxLength < 0) {
      return "";
    }
    String result = (String) input;
    if (result.length() > maxLength) {
      log.debug("Parameter too long: " + result.length() + " characters");
      return "";
    }
    return result;
  }

  /**
   * Session is checked for credentials and ensures that they have not been modified and that they
   * are valid
   *
   * @param ses HttpSession from users browser
   * @return Boolean value that reflects the validity of the users session
   */
  public static boolean validateSession(HttpSession ses) {
    boolean result = false;
    if (ses == null) {
      log.debug("No Session Found");
    } else {
      if (ses.getAttribute("logout") != null) {
        log.debug("Logout Attribute Found: Invalidating session...");
        ses.invalidate(); // make servlet engine forget the session
      } else {
        // log.debug("Active Session Found");
        if (ses.getAttribute("userRole") instanceof String
            && ses.getAttribute("userName") instanceof String
            && !((String) ses.getAttribute("userName")).isEmpty()) {
          try {
            // log.debug("Session holder is "+ses.getAttribute("userName").toString());
            String role = (String) ses.getAttribute("userRole");
            result = (role.compareTo("player") == 0 || role.compareTo("admin") == 0);
            if (!result) {
              log.fatal("User Role Parameter Tampered. Role = " + role);
            } else {
              String userName = ses.getAttribute("userName").toString();
              // Has the user been suspended? Should they be kicked?
              if (UserKicker.shouldKickUser(userName)) {
                log.debug(
                    userName
                        + " has been Suspended. Invalidating Session and Reporting Invalid"
                        + " Session");
                ses.invalidate(); // Killing Session
                result = false; // User will not access function they were attempting to call
                UserKicker.removeFromKicklist(userName); // Removing from kick list, as they are now
                // authenticated, the DB Layer Suspension
                // will prevent them from signing in
              }
            }
          } catch (Exception e) {
            log.fatal("Tampered Parameter Detected!!! Could not Decrypt stamp");
            result = false;
          }
        } else {
          log.debug("Session has no credentials");
        }
      }
    }
    return result;
  }

  /**
   * This method compares the two submitted tokens after ensuring they are not null and not empty.
   *
   * @param cookieToken CSRF cookie Token
   * @param requestToken CSRF request Token
   * @return A boolean value stating weather or not the tokens are valid
   */
  public static boolean validateTokens(Cookie cookieToken, Object requestToken) {
    boolean result = false;
    boolean cookieNull = (cookieToken == null);
    boolean requestNull = (requestToken == null);
    if (!cookieNull && !requestNull) {

      if (!(requestToken instanceof String)) {
        log.error("Request Token had an unexpected type");
        return false;
      }

      String theRequest = (String) requestToken;
      String theCookie = cookieToken.getValue();
      boolean cookieEmpty = theCookie.isEmpty();
      boolean requestEmpty = theRequest.isEmpty();

      if (!cookieEmpty && !requestEmpty) {
        result = constantTimeEquals(theRequest, theCookie);
      } else if (cookieEmpty) {
        log.error("Cookie Token Empty");
      } else if (requestEmpty) {
        log.error("Request Token Empty");
      }

      if (!result) {
        log.error("CSRF Tokens did not match");
      }

    } else {
      if (cookieNull) {
        log.error("Cookie Token was Null");
      } else if (requestNull) {
        log.error("Request Token was Null");
      }
    }
    return result;
  }

  /** Validates that the request and cookie tokens match the authenticated session's token. */
  public static boolean validateTokens(
      HttpSession session, Cookie cookieToken, Object requestToken) {
    if (session == null
        || cookieToken == null
        || !(requestToken instanceof String)
        || !(session.getAttribute("csrfToken") instanceof String)) {
      log.error("CSRF token data was missing or invalid");
      return false;
    }

    String sessionToken = (String) session.getAttribute("csrfToken");
    String cookieValue = cookieToken.getValue();
    String requestValue = (String) requestToken;
    boolean result =
        !sessionToken.isEmpty()
            && constantTimeEquals(sessionToken, cookieValue)
            && constantTimeEquals(sessionToken, requestValue);
    if (!result) {
      log.error("CSRF tokens did not match the authenticated session");
    }
    return result;
  }

  /** Validates a request token against a pre-authentication session, such as registration. */
  public static boolean validateSessionToken(HttpSession session, Object requestToken) {
    if (session == null
        || !(requestToken instanceof String)
        || !(session.getAttribute("csrfToken") instanceof String)) {
      return false;
    }
    String sessionToken = (String) session.getAttribute("csrfToken");
    return !sessionToken.isEmpty() && constantTimeEquals(sessionToken, (String) requestToken);
  }

  private static boolean constantTimeEquals(String first, String second) {
    return first != null
        && second != null
        && MessageDigest.isEqual(
            first.getBytes(StandardCharsets.UTF_8), second.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Validates file name attributes to defend against path traversal
   *
   * @param fileName File name to validate
   * @return Boolean value reflecting if valid or not
   */
  /*
   * public static String validateFileName(String fileName) {
   * ShepherdLogManager.logEvent(request.getRemoteAddr(),
   * request.getHeader("X-Forwarded-For"), "fileName: " + fileName); fileName =
   * fileName.replaceAll(" ", "").replaceAll("\\.", "").replaceAll("/",
   * "").replaceAll("\\\\", "").replaceAll("\n", "");
   * ShepherdLogManager.logEvent(request.getRemoteAddr(),
   * request.getHeader("X-Forwarded-For"), "fileName: " + fileName); return
   * fileName; }
   */
  public static boolean validHostUrl(String hostUrl) {
    // TODO - Pull other validation steps into this
    boolean result;
    result = hostUrl != null && hostUrl.endsWith("/");
    if (!result) {
      log.error("URL Doesn't end with a forward slash. Very likely wrong");
    }
    return result;
  }

  /**
   * Validates that a port number supplied is a valid port number
   *
   * @param portNum String to validate
   * @return Boolean value reflecting if valid or not
   */
  public static boolean isValidPortNumber(String portNum) {
    if (portNum == null || !portNum.matches("[0-9]{1,5}")) {
      log.error("Invalid port number supplied");
      return false;
    }
    try {
      Integer validPort = Integer.valueOf(portNum);
      if (validPort < 1 || validPort > 65535) {
        log.error("Port number was outside the valid range");
        return false;
      }
    } catch (NumberFormatException e) {
      log.error("Invalid port number supplied");
      return false;
    }
    return true;
  }
}
