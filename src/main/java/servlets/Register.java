package servlets;

import dbProcs.Getter;
import dbProcs.Setter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.OpenRegistration;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Control class for the Registration process. <br>
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
public class Register extends HttpServlet {

  private static final long serialVersionUID = -2558345286276614261L;
  private static final Logger log = LogManager.getLogger(Register.class);
  private static String defaultClass = new String();
  private static boolean isLoaded = false;

  /**
   * Initiated by register.jsp. If successful a player is added to the system, otherwise there is no
   * change. Adding the player to the database is handled by the dbProcs.Setter class. Email is
   * stored for future application expansion This function will request requests if the
   * application's registration functionality has been marked as closed by administration.
   *
   * @param userName User's User Name
   * @param passWord User's Password
   * @param passWordConfirm Password Confirmation
   * @param userAddress User's Email
   * @param userAddressCnf User's Email Confirmation
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from
    // proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug("**** servlets.Register ***");
    PrintWriter out = response.getWriter();
    response.setCharacterEncoding("UTF-8");
    request.setCharacterEncoding("UTF-8");
    out.print(getServletInfo());
    if (OpenRegistration.isEnabled()) {
      HttpSession ses = request.getSession(true);
      boolean notNull = false;
      boolean notEmpty = false;
      boolean validPasswords = false;
      boolean validAddress = false;
      boolean userValidate = false;
      try {
        log.debug("Getting ApplicationRoot");
        String ApplicationRoot = getServletContext().getRealPath("");
        log.debug("Servlet root = " + ApplicationRoot);

        request.setCharacterEncoding("UTF-8");

        log.debug("Ensuring not a CSRF");
        String paramToken = (String) request.getParameter("csrfToken");
        if (Validate.validateSessionToken(ses, paramToken)) {
          log.debug("Getting Registration Parameters");
          String userName = (String) request.getParameter("userName");
          String passWord = (String) request.getParameter("passWord");
          log.debug("passWord retrieved");
          String passWordConfirm = (String) request.getParameter("passWordConfirm");
          log.debug("passWordConfirm retrieved");
          String userAddress = (String) request.getParameter("userAddress");
          String userAddressCnf = (String) request.getParameter("userAddressCnf");

          // Validation
          log.debug("Checking for nulls");
          notNull =
              userName != null
                  && passWord != null
                  && passWordConfirm != null
                  && userAddress != null
                  && userAddressCnf != null;
          log.debug("Ensuring strings are not empty");
          notEmpty = notNull && !userName.isEmpty() && !passWord.isEmpty();
          log.debug("Validating passwords");
          validPasswords = notNull && passWord.equals(passWordConfirm);
          log.debug("Validating addresses");
          validAddress =
              notNull
                  && userAddress.equals(userAddressCnf)
                  && (userAddress.isEmpty() || Validate.isValidEmailAddress(userAddress));
          boolean basicValidation = validPasswords && validAddress && notNull && notEmpty;
          userValidate =
              validRegistrationFields(
                  userName, passWord, passWordConfirm, userAddress, userAddressCnf);
          if (basicValidation && userValidate) {
            // Data is good, Add user
            // Any Class Set to Add them to?
            if (!isLoaded) {
              try {
                defaultClass = Getter.getDefaultClass("");
                isLoaded = true;
              } catch (SQLException e) {
                log.fatal("Could not load default class: " + e.toString());
                throw new RuntimeException(e);
              }
            }
            if (defaultClass.isEmpty()) {
              log.debug("Adding player to database, with null classId");
              Setter.userCreate(
                  ApplicationRoot, null, userName, passWord, "player", userAddress, false);
            } else // defaultClass is not empty, so It must be set to a class!
            {
              log.debug("Adding player to database, to class " + defaultClass);
              Setter.userCreate(
                  ApplicationRoot, defaultClass, userName, passWord, "player", userAddress, false);
            }
            response.sendRedirect("login.jsp");
          } else {
            // Validation Error Responses
            if (!notNull || !notEmpty) {
              log.error("Null values detected");
              ses.setAttribute("errorMessage", "Invalid Request. Please try again");
            } else if (!validPasswords) {
              log.error("Passwords did not match");
              ses.setAttribute("errorMessage", "Password fields did not match");
            } else if (!validAddress) {
              log.error("Invalid Addresses Detected");
              ses.setAttribute("errorMessage", "Invalid Request. Please try again");
            } else if (!userValidate) {
              log.error("Invalid Addresses Detected");
              ses.setAttribute("errorMessage", "");
            }
            response.sendRedirect("register.jsp");
          }
        } else {
          log.warn("Registration request rejected because its CSRF token was invalid");
        }
      } catch (Exception e) {
        log.error("Registration Error: " + e.toString());
        ses.setAttribute("errorMessage", "An error Occurred. Please try again");
        response.sendRedirect("register.jsp");
      }
    } else {
      out.write("Registration is not open");
    }
    log.debug("*** Register END ***");
  }

  /** Redirects to index.jsp */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.sendRedirect("index.jsp");
  }

  static boolean validRegistrationFields(
      String userName,
      String password,
      String passwordConfirmation,
      String address,
      String addressConfirmation) {
    return userName != null
        && password != null
        && passwordConfirmation != null
        && address != null
        && addressConfirmation != null
        && password.equals(passwordConfirmation)
        && address.equals(addressConfirmation)
        && (address.isEmpty() || Validate.isValidEmailAddress(address))
        && Validate.isValidUser(userName, password, address);
  }

  public static String getDefaultClass() {
    if (!isLoaded) {
      try {
        defaultClass = Getter.getDefaultClass("");
        isLoaded = true;
      } catch (SQLException e) {
        log.fatal("Could not load default class: " + e.toString());
        throw new RuntimeException(e);
      }
    }

    return defaultClass;
  }

  public static void setDefaultClass(String theDefaultClass) {
    defaultClass = theDefaultClass;
    try {
      Setter.setDefaultClass("", theDefaultClass);
    } catch (SQLException e) {
      log.fatal("Could not save default class: " + e.toString());
      throw new RuntimeException(e);
    }
    isLoaded = true;
  }
}
