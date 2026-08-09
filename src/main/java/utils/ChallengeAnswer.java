package utils;

import dbProcs.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Keeps a module's own answer out of the data a challenge hands back.
 *
 * <p>Several of the injection challenges keep their result key in a row of the same table the
 * feature searches. Binding the query stops the search being rewritten, but it does not stop the
 * row being asked for by name or by identifier, so the answer was still reachable through the
 * application working exactly as intended. A feature has no reason to serve the value that proves
 * the feature was broken, so rows carrying it are dropped before anything is written out.
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
 */
public class ChallengeAnswer {

  private static final Logger log = LogManager.getLogger(ChallengeAnswer.class);

  /**
   * Looks up the stored answer for a module.
   *
   * @param applicationRoot Running context of the application
   * @param levelHash Hash identifying the module
   * @return The module's stored answer, or null when it could not be read
   */
  public static String forLevel(String applicationRoot, String levelHash) {
    try {
      return Getter.getModuleResultFromHash(applicationRoot, levelHash);
    } catch (Exception e) {
      log.error("Could not read the module answer to filter it out: " + e.toString());
      return null;
    }
  }

  /**
   * Reports whether any of the supplied column values carries the module's answer.
   *
   * @param answer The module's stored answer, as returned by forLevel
   * @param columns Column values from one row of a result set
   * @return True when the row would hand the answer to the caller
   */
  public static boolean rowRevealsAnswer(String answer, String... columns) {
    if (answer == null || answer.isEmpty()) {
      return false;
    }
    for (String column : columns) {
      if (column != null && column.contains(answer)) {
        return true;
      }
    }
    return false;
  }
}
