package utils;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;

/**
 * CSRF nonce utility — generates and validates a per-session SecureRandom token.
 *
 * <p>This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 */
public class CsrfNonce {

  private static final String SESSION_ATTR = "csrfNonce";
  private static final SecureRandom RANDOM = new SecureRandom();

  private CsrfNonce() {}

  /**
   * Returns the existing CSRF nonce stored in the session, or lazily creates a new one using
   * SecureRandom and stores it before returning.
   *
   * @param session the current HTTP session
   * @return a Base64-encoded 32-byte CSRF nonce
   */
  public static String getOrCreate(HttpSession session) {
    Object existing = session.getAttribute(SESSION_ATTR);
    if (existing != null) {
      return existing.toString();
    }
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String token = Base64.getEncoder().encodeToString(bytes);
    session.setAttribute(SESSION_ATTR, token);
    return token;
  }

  /**
   * Validates the submitted token against the one stored in the session using a constant-time
   * comparison to prevent timing attacks. Returns false if either value is null or missing.
   *
   * @param session the current HTTP session
   * @param submitted the token value submitted by the client
   * @return true only when both values are non-null and equal
   */
  public static boolean isValid(HttpSession session, String submitted) {
    if (session == null || submitted == null) {
      return false;
    }
    Object stored = session.getAttribute(SESSION_ATTR);
    if (stored == null) {
      return false;
    }
    byte[] storedBytes = stored.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] submittedBytes = submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    return MessageDigest.isEqual(storedBytes, submittedBytes);
  }
}
