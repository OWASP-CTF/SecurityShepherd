package servlets.api;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import utils.ScoreboardStatus;
import utils.Validate;

@WebServlet("/api/scoreboard")
public class Scoreboard extends HttpServlet {

  private static final long serialVersionUID = 1L;

  /** Get request just returns if the session can access the scoreboard or not */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    HttpSession ses = request.getSession(true);

    // A public scoreboard is deliberately readable without signing in, so an anonymous caller is
    // still allowed through as a null role. What must not happen is trusting a role attribute from
    // a session that no longer validates, so only a validated session contributes a role.
    String userRole = Validate.validateSession(ses) ? (String) ses.getAttribute("userRole") : null;

    if (ScoreboardStatus.canSeeScoreboard(userRole)) {
      out.write("true");
    } else {
      // Return 403
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
  }
}
