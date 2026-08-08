package servlets;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SetupFilter implements Filter {

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    //
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;
    response.setCharacterEncoding("UTF-8");
    request.setCharacterEncoding("UTF-8");

    if (!Setup.isInstalled()) {
      if (isSetupResource(req)) {
        chain.doFilter(request, response);
      } else {
        res.sendRedirect(req.getContextPath() + "/setup.jsp");
      }
    } else {
      chain.doFilter(request, response);
    }
  }

  @Override
  public void destroy() {
    //
  }

  static boolean isSetupResource(HttpServletRequest request) {
    String requestUri = request.getRequestURI();
    if (requestUri == null) {
      return false;
    }
    String contextPath = request.getContextPath();
    if (contextPath != null && !contextPath.isEmpty() && requestUri.startsWith(contextPath)) {
      requestUri = requestUri.substring(contextPath.length());
    }
    return "/setup".equals(requestUri)
        || "/setup.jsp".equals(requestUri)
        || requestUri.startsWith("/css/")
        || requestUri.startsWith("/js/");
  }
}
