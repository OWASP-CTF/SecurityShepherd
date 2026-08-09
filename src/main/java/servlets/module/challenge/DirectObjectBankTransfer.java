package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Insecure Direct Object Reference Bank Challenge Transfer Funds Function DOES NOT RETURN RESULT
 * KEY <br>
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
public class DirectObjectBankTransfer extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(DirectObjectBankTransfer.class);
  private static String levelName = "Insecure Direct Object Bank Challenge (Transfer)";
  public static String levelHash =
      "1f0935baec6ba69d79cfb2eba5fdfa6ac5d77fadee08585eb98b130ec524d00c";

  /**
   * This Servlet is used to transfer funds from one bank account to another, insecurely, in the
   * Direct Object Reference Bank challenge
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle("i18n.servlets.challenges.directObject.directObjectBank", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      boolean performTransfer = false;
      String errorMessage = new String();
      String applicationRoot = getServletContext().getRealPath("");
      Connection conn = null;
      try {
        // Funds may only be sent from the account signed into this session
        Object bankAccount = ses.getAttribute("directObjectBankAccount");
        if (bankAccount == null) {
          log.debug("No bank account signed into this session");
          out.write(errors.getString("error.noSession"));
          return;
        }
        String senderAccountNumber = bankAccount.toString();
        log.debug("Sender Account Number - " + senderAccountNumber);
        String receiverAccountNumber = request.getParameter("receiverAccountNumber");
        log.debug("Receiver Account Number - " + receiverAccountNumber);
        String transferAmountString = request.getParameter("transferAmount");
        log.debug("Transfer Amount - " + transferAmountString);
        // Parsed and compared as a double: a long balance loses precision in a float
        double tranferAmount = Double.parseDouble(transferAmountString);

        // Data Validation
        // Positive Transfer Amount?
        if (tranferAmount > 0) {
          // Sender Account Has necessary funds?
          long senderFunds =
              DirectObjectBankLogin.getAccountBalance(senderAccountNumber, applicationRoot);
          if ((senderFunds - tranferAmount) > 0) {
            // Check Receiver Account Exists
            try {
              long receiverAccountBalance =
                  DirectObjectBankLogin.getAccountBalance(receiverAccountNumber, applicationRoot);
              if (receiverAccountBalance >= 0) {
                performTransfer = true;
              }
            } catch (Exception e) {
              log.debug("Receiver Account does not exist. Cancelling");
              errorMessage = bundle.getString("transfer.error.receiverNotFound");
            }
          } else {
            errorMessage = bundle.getString("transfer.error.notEnoughCash");
          }
        } else {
          errorMessage = bundle.getString("transfer.error.moreThanZero");
        }

        String htmlOutput = new String();
        if (performTransfer) {
          log.debug("Valid Data Submitted, transfering Funds...");
          conn = Database.getChallengeConnection(applicationRoot, "directObjectBank");
          CallableStatement callstmt = conn.prepareCall("CALL transferFunds(?, ?, ?)");
          callstmt.setString(1, senderAccountNumber);
          callstmt.setString(2, receiverAccountNumber);
          callstmt.setDouble(3, tranferAmount);
          // The procedure re-checks the balance inside the transaction that debits it, so two
          // concurrent transfers cannot both pass the check above and overdraw the account
          ResultSet transferResult = callstmt.executeQuery();
          if (transferResult.next() && transferResult.getInt(1) > 0) {
            log.debug("Successfully ran Transfer Funds procedure.");
            htmlOutput = bundle.getString("transfer.success");
          } else {
            log.debug("Transfer rejected, sender had insufficient funds");
            htmlOutput =
                bundle.getString("transfer.error.occurred")
                    + " "
                    + bundle.getString("transfer.error.notEnoughCash");
          }
          transferResult.close();
        } else {
          log.debug("Invalid Data Detected: " + errorMessage);
          htmlOutput = bundle.getString("transfer.error.occurred") + " " + errorMessage;
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (SQLException e) {
        out.write(
            errors.getString("error.funky")
                + " "
                + bundle.getString("transfer.error.couldNotTransfer"));
        log.fatal(levelName + " SQL Error - " + e.toString());
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      } finally {
        Database.closeConnection(conn);
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
