package servlets;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

class SecurityHeadersFilterTest {

  @Test
  void doFilter_addsBrowserSecurityHeaders() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);
    when(request.isSecure()).thenReturn(true);

    new SecurityHeadersFilter().doFilter(request, response, chain);

    verify(response).setHeader("X-Content-Type-Options", "nosniff");
    verify(response).setHeader("X-Frame-Options", "SAMEORIGIN");
    verify(response).setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    verify(response).setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    verify(chain).doFilter(request, response);
  }
}
