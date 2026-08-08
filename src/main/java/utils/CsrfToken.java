package utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/** Creates and removes CSRF tokens used by the authenticated platform. */
public final class CsrfToken {

  private CsrfToken() {}

  public static String issue(
      HttpServletRequest request, HttpServletResponse response, HttpSession session) {
    String value = Hash.randomString();
    session.setAttribute("csrfToken", value);
    response.addCookie(createCookie(value, request.isSecure(), request.getContextPath()));
    return value;
  }

  public static void expire(HttpServletRequest request, HttpServletResponse response) {
    response.addCookie(expiredCookie(request.isSecure(), request.getContextPath()));
  }

  static Cookie createCookie(String value, boolean secure, String contextPath) {
    Cookie cookie = new Cookie("token", value);
    cookie.setHttpOnly(true);
    cookie.setSecure(secure);
    cookie.setPath(cookiePath(contextPath));
    return cookie;
  }

  static Cookie expiredCookie(boolean secure, String contextPath) {
    Cookie cookie = createCookie("", secure, contextPath);
    cookie.setMaxAge(0);
    return cookie;
  }

  private static String cookiePath(String contextPath) {
    return contextPath == null || contextPath.isEmpty() ? "/" : contextPath;
  }
}
