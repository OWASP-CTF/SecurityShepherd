package servlets;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** Adds browser-enforced security policy to all platform and static responses. */
public class SecurityHeadersFilter implements Filter {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    httpResponse.setHeader("X-Content-Type-Options", "nosniff");
    httpResponse.setHeader("X-Frame-Options", "SAMEORIGIN");
    httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    httpResponse.setHeader(
        "Content-Security-Policy", "base-uri 'self'; frame-ancestors 'self'; object-src 'none'");
    httpResponse.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
    if (httpRequest.isSecure()) {
      httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }

    chain.doFilter(request, response);
  }
}
