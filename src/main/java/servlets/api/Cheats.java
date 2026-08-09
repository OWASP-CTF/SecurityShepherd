package servlets.api;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import utils.CheatSheetStatus;
import utils.Validate;

@WebServlet("/api/cheats")
public class Cheats extends HttpServlet {

  private static final long serialVersionUID = 1L;

  /** Get request just returns if the session can access the cheat sheets or not */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    HttpSession ses = request.getSession(true);

    // Cheat sheets are only for signed in users. Reading userRole straight off the session skipped
    // validateSession, so a tampered role attribute, or the session of a user who has since been
    // suspended and kicked, was trusted here.
    if (!Validate.validateSession(ses)) {
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    if (CheatSheetStatus.showCheat((String) ses.getAttribute("userRole"))) {
      out.write("true");
    } else {
      // Return 403
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
  }
}
