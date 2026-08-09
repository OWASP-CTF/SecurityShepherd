package servlets;

import dbProcs.Getter;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** Prevents direct requests from bypassing the module open/closed setting. */
public class ModuleStatusFilter implements Filter {

  private static final int MODULE_HASH_LENGTH = 64;
  private ServletContext servletContext;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    servletContext = filterConfig.getServletContext();
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    String moduleHash = getModuleHash(httpRequest.getServletPath());

    if (moduleHash != null) {
      String applicationRoot = servletContext.getRealPath("");
      String moduleId = Getter.getModuleIdFromHash(applicationRoot, moduleHash);
      if (moduleId != null
          && !moduleId.isEmpty()
          && !Getter.isModuleOpen(applicationRoot, moduleId)) {
        httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
        return;
      }
    }

    chain.doFilter(request, response);
  }

  private static String getModuleHash(String servletPath) {
    String prefix = "/challenges/";
    if (servletPath == null || !servletPath.startsWith(prefix)) {
      return null;
    }

    String target = servletPath.substring(prefix.length());
    if (target.length() < MODULE_HASH_LENGTH) {
      return null;
    }

    String candidate = target.substring(0, MODULE_HASH_LENGTH);
    for (int i = 0; i < candidate.length(); i++) {
      if (!Character.isLetterOrDigit(candidate.charAt(i))) {
        return null;
      }
    }
    return candidate;
  }
}
