package utils;

import dbProcs.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Screens a query result for a challenge's own stored answer before it is written out.
 *
 * <p>A handful of the injection challenges keep their result key in the same table (or a sibling
 * row of the same table) that the vulnerable feature searches. Binding the query stops the
 * statement from being rewritten, but it does nothing to stop the row itself being reached - by a
 * lucky guess, a brute-forced key, or an injection technique nobody anticipated - and a feature
 * has no legitimate reason to hand back the value that proves it was ever broken. Rows carrying it
 * are withheld regardless of how they were reached.
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
public final class ResultLeakGuard {

  private static final Logger log = LogManager.getLogger(ResultLeakGuard.class);

  private ResultLeakGuard() {}

  /**
   * Looks up the answer a module hands out on success, so it can be screened for.
   *
   * @param applicationRoot Running context of the application
   * @param levelHash Hash identifying the module
   * @return The module's stored answer, or null when it could not be read
   */
  public static String lookupAnswer(String applicationRoot, String levelHash) {
    try {
      return Getter.getModuleResultFromHash(applicationRoot, levelHash);
    } catch (Exception e) {
      log.error("Could not look up the module answer to screen for it: " + e.toString());
      return null;
    }
  }

  /**
   * Reports whether any of the supplied values would hand the module's answer back to the caller.
   *
   * @param answer The module's stored answer, as returned by lookupAnswer
   * @param values Values drawn from one row of a result set
   * @return True when one of the values carries the answer
   */
  public static boolean leaksAnswer(String answer, String... values) {
    if (answer == null || answer.isEmpty()) {
      return false;
    }
    for (String value : values) {
      if (value != null && value.contains(answer)) {
        return true;
      }
    }
    return false;
  }
}
