package utils;

import dbProcs.Database;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Server side identity and role resolution for the Failure to Restrict URL Access challenges. <br>
 * <br>
 * The simulated applications used by these levels sign the player in as a guest account. Both the
 * identity and the role of that account are held in the user's HttpSession, which only the server
 * can write. No request parameter, cookie, header or URL can promote a caller, so knowing the URL
 * of an administrative function is no longer an authorisation to invoke it. <br>
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
 */
public class UrlAccessIdentity {

  private static final Logger log = LogManager.getLogger(UrlAccessIdentity.class);

  /** Session attribute holding the simulated application user bound to this session. */
  public static final String CURRENT_PERSON_KEY = "urlAccessCurrentPerson";

  /** Session attribute holding the role the server granted inside the simulated application. */
  public static final String CURRENT_ROLE_KEY = "urlAccessCurrentRole";

  /** The only account the simulated application signs a player in as. */
  public static final String GUEST_USER = "aGuest";

  /** Least privileged role of the simulated application. */
  public static final String GUEST_ROLE = "guest";

  /** Role required to invoke an administrative function of the simulated application. */
  public static final String ADMIN_ROLE = "admin";

  /** Role required to enter the super admin only area of the simulated application. */
  public static final String SUPER_ADMIN_ROLE = "superadmin";

  private UrlAccessIdentity() {}

  /**
   * Returns the simulated application user bound to this session, defaulting to the guest account.
   *
   * @param ses HttpSession of the caller
   * @return The user name of the sub application account bound to this session
   */
  public static String getCurrentPerson(HttpSession ses) {
    if (ses == null) {
      return GUEST_USER;
    }
    Object currentPerson = ses.getAttribute(CURRENT_PERSON_KEY);
    if (currentPerson instanceof String && !((String) currentPerson).isEmpty()) {
      return (String) currentPerson;
    }
    ses.setAttribute(CURRENT_PERSON_KEY, GUEST_USER);
    return GUEST_USER;
  }

  /**
   * Resolves the role of the session bound sub application user from the challenge database. Fails
   * closed: any problem resolving the role returns the least privileged role.
   *
   * @param ses HttpSession of the caller
   * @param applicationRoot Running context of the application
   * @return The role of the session bound sub application user
   */
  public static String getCurrentRole(HttpSession ses, String applicationRoot) {
    if (ses == null) {
      return GUEST_ROLE;
    }
    Object grantedRole = ses.getAttribute(CURRENT_ROLE_KEY);
    if (grantedRole instanceof String && !((String) grantedRole).isEmpty()) {
      return (String) grantedRole;
    }
    String currentPerson = getCurrentPerson(ses);
    String role = GUEST_ROLE;
    try (Connection conn = Database.getChallengeConnection(applicationRoot, "UrlAccessThree");
        PreparedStatement roleStatement =
            conn.prepareStatement("SELECT userRole FROM users WHERE userName = ?")) {
      roleStatement.setString(1, currentPerson);
      try (ResultSet rs = roleStatement.executeQuery()) {
        if (rs.next() && rs.getString(1) != null) {
          role = rs.getString(1);
        }
      }
    } catch (Exception e) {
      log.error("Could not resolve URL Access role, defaulting to guest: " + e.toString());
      role = GUEST_ROLE;
    }
    ses.setAttribute(CURRENT_ROLE_KEY, role);
    return role;
  }

  /**
   * Authorisation check for the administrative functions of the simulated applications. The role is
   * server side session state only.
   *
   * @param ses HttpSession of the caller
   * @return True only when the server itself granted this session an administrative role
   */
  public static boolean isAdministrator(HttpSession ses) {
    if (ses == null) {
      return false;
    }
    Object role = ses.getAttribute(CURRENT_ROLE_KEY);
    return (role instanceof String) && (ADMIN_ROLE.equals(role) || SUPER_ADMIN_ROLE.equals(role));
  }
}
