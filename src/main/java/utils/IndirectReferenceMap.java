package utils;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Per session map from an opaque handle to the identifier of a record the session may read.
 *
 * <p>A feature that puts a record's own identifier in the page hands the caller the ability to name
 * any other record, and no amount of dressing up that identifier changes it: counting up from one
 * is guessable, and a digest of a small number is guessable by digesting small numbers. The remedy
 * is not to make the reference harder to read but to stop it being a reference to the record at
 * all. The handles minted here are drawn from a CSPRNG, mean nothing outside the session they were
 * issued to, and resolve only to the records that session was actually offered, so an identifier
 * the application never published cannot be asked for.
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
public class IndirectReferenceMap {

  private static final Logger log = LogManager.getLogger(IndirectReferenceMap.class);

  /** Prefix of the session attribute each namespace's map is held under. */
  private static final String ATTRIBUTE_PREFIX = "indirectReferenceMap.";

  /** Bytes of randomness behind each handle. */
  private static final int HANDLE_LENGTH = 16;

  private static final SecureRandom random = new SecureRandom();

  /**
   * Returns the handle this session uses for a record, minting one if the record has not been
   * offered to this session before.
   *
   * @param ses Session the handle is being issued to
   * @param namespace Names the set of records the handle belongs to, so two challenges cannot
   *     resolve each other's handles
   * @param directReference The record identifier the handle stands in for
   * @return An opaque handle to publish in place of the record identifier
   */
  public static String handleFor(HttpSession ses, String namespace, String directReference) {
    Map<String, String> references = mapFor(ses, namespace);
    synchronized (references) {
      for (Map.Entry<String, String> reference : references.entrySet()) {
        if (reference.getValue().equals(directReference)) {
          return reference.getKey();
        }
      }
      byte[] handleBytes = new byte[HANDLE_LENGTH];
      random.nextBytes(handleBytes);
      String handle = Hex.encodeHexString(handleBytes);
      references.put(handle, directReference);
      return handle;
    }
  }

  /**
   * Resolves a handle submitted in a request back to the record it stands for.
   *
   * @param ses Session the handle is claimed to have been issued to
   * @param namespace Names the set of records the handle should belong to
   * @param handle Handle as submitted by the client
   * @return The record identifier, or null when this session was never offered that record
   */
  public static String resolve(HttpSession ses, String namespace, String handle) {
    if (handle == null || handle.isEmpty()) {
      log.debug("No object reference was submitted");
      return null;
    }
    String directReference = mapFor(ses, namespace).get(handle);
    if (directReference == null) {
      log.error("An object reference that was never issued to this session was submitted");
    }
    return directReference;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, String> mapFor(HttpSession ses, String namespace) {
    String attribute = ATTRIBUTE_PREFIX + namespace;
    synchronized (ses) {
      Map<String, String> references = (Map<String, String>) ses.getAttribute(attribute);
      if (references == null) {
        references = Collections.synchronizedMap(new HashMap<String, String>());
        ses.setAttribute(attribute, references);
      }
      return references;
    }
  }
}
