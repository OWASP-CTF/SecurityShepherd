package utils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Per session indirect object reference maps for the Insecure Direct Object Reference challenges.
 * The client is only ever handed an unpredictable, session scoped handle for the profiles it is
 * authorised to read. The real database identifier never leaves the server, and a submitted value
 * is only ever honoured when it maps to, or is a member of, the server side allow list of profiles
 * this feature is permitted to expose. <br>
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
public class DirectObjectReferenceMap {

  private static final Logger log = LogManager.getLogger(DirectObjectReferenceMap.class);

  /** Session attribute holding the reference map of Insecure Direct Object Reference One. */
  private static final String CHALLENGE_ONE_ATTRIBUTE = "directObjectRefChalOneReferenceMap";

  /** Session attribute holding the reference map of Insecure Direct Object Reference Two. */
  private static final String CHALLENGE_TWO_ATTRIBUTE = "directObjectRefChalTwoReferenceMap";

  /** The only profiles challenge one is authorised to expose: {userId, displayName}. */
  private static final String[][] CHALLENGE_ONE_PROFILES = {
    {"1", "Paul Bourke"},
    {"3", "Will Bailey"},
    {"5", "Orla Cleary"},
    {"7", "Ronan Fitzpatrick"},
    {"9", "Pat McKenana"}
  };

  /** The only profiles challenge two is authorised to expose: {userId, displayName}. */
  private static final String[][] CHALLENGE_TWO_PROFILES = {
    {"c81e728d9d4c2f636f067f89cc14862c", "Joe Sullivan"},
    {"eccbc87e4b5ce2fe28308fd9f2a7baf3", "Will Bailey"},
    {"e4da3b7fbbce2345d7772b0674a318d5", "Orla Cleary"},
    {"8f14e45fceea167a5a36dedd4bea2543", "Ronan Fitzpatrick"},
    {"6512bd43d9caa6e02c990b0a82652dca", "Pat McKenana"}
  };

  private DirectObjectReferenceMap() {}

  /**
   * Returns this session's indirect reference map for Insecure Direct Object Reference Challenge
   * One, creating it on first use.
   *
   * @param ses The current user session
   * @return Unmodifiable, insertion ordered map of indirect reference to {userId, displayName}
   */
  public static Map<String, String[]> getChallengeOneMap(HttpSession ses) {
    return getReferenceMap(ses, CHALLENGE_ONE_ATTRIBUTE, CHALLENGE_ONE_PROFILES);
  }

  /**
   * Returns this session's indirect reference map for Insecure Direct Object Reference Challenge
   * Two, creating it on first use.
   *
   * @param ses The current user session
   * @return Unmodifiable, insertion ordered map of indirect reference to {userId, displayName}
   */
  public static Map<String, String[]> getChallengeTwoMap(HttpSession ses) {
    return getReferenceMap(ses, CHALLENGE_TWO_ATTRIBUTE, CHALLENGE_TWO_PROFILES);
  }

  /**
   * Authorisation decision for Insecure Direct Object Reference Challenge One. The submitted value
   * is honoured only when it is one of this session's own indirect references, or when it names a
   * profile that is on the server side allow list of publicly readable profiles.
   *
   * @param ses The current user session
   * @param submittedReference The value submitted by the client
   * @return The real userId the caller is authorised to read, or null when there is none
   */
  public static String resolveChallengeOneReference(HttpSession ses, String submittedReference) {
    return resolve(getChallengeOneMap(ses), CHALLENGE_ONE_PROFILES, submittedReference);
  }

  /**
   * Authorisation decision for Insecure Direct Object Reference Challenge Two. The submitted value
   * is honoured only when it is one of this session's own indirect references, or when it names a
   * profile that is on the server side allow list of publicly readable profiles.
   *
   * @param ses The current user session
   * @param submittedReference The value submitted by the client
   * @return The real userId the caller is authorised to read, or null when there is none
   */
  public static String resolveChallengeTwoReference(HttpSession ses, String submittedReference) {
    return resolve(getChallengeTwoMap(ses), CHALLENGE_TWO_PROFILES, submittedReference);
  }

  private static String resolve(
      Map<String, String[]> referenceMap, String[][] profiles, String submittedReference) {
    if (submittedReference == null || submittedReference.isEmpty()) {
      return null;
    }
    String[] mappedProfile = referenceMap.get(submittedReference);
    if (mappedProfile != null) {
      return mappedProfile[0];
    }
    for (String[] profile : profiles) {
      if (profile[0].equals(submittedReference)) {
        return profile[0];
      }
    }
    log.error("Unauthorised object reference submitted");
    return null;
  }

  private static Map<String, String[]> getReferenceMap(
      HttpSession ses, String attributeName, String[][] profiles) {
    synchronized (ses) {
      Object storedMap = ses.getAttribute(attributeName);
      if (storedMap instanceof Map<?, ?>) {
        @SuppressWarnings("unchecked")
        Map<String, String[]> existingMap = (Map<String, String[]>) storedMap;
        return existingMap;
      }
      Map<String, String[]> newMap = new LinkedHashMap<String, String[]>();
      for (String[] profile : profiles) {
        newMap.put(Hash.randomString(), new String[] {profile[0], profile[1]});
      }
      Map<String, String[]> referenceMap = Collections.unmodifiableMap(newMap);
      ses.setAttribute(attributeName, referenceMap);
      log.debug("Created indirect object reference map: " + attributeName);
      return referenceMap;
    }
  }
}
