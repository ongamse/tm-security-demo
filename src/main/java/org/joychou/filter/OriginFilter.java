package org.joychou.filter;


import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 推荐使用该全局方案修复Cors跨域漏洞，因为可以校验一级域名。
 *
 * @author JoyChou @ 2019.12.19
 */
@WebFilter(filterName = "OriginFilter", urlPatterns = "/cors/sec/originFilter")
public class OriginFilter implements Filter {

    private static final List<String> ALLOWED_ORIGINS = Arrays.asList(
            "http://test.joychou.me",
            "https://joychou.org"
    );

    /**
     * Match a request origin against the hardcoded ALLOWED_ORIGINS list.
     * Returns the matched entry from the list (not the user-supplied value)
     * to break taint flow from request header to response header.
     */
    private static String matchAllowedOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        for (String allowed : ALLOWED_ORIGINS) {
            if (allowed.equalsIgnoreCase(origin)) {
                return allowed;
            }
        }
        return null;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String origin = request.getHeader("Origin");
        logger.info("[+] Origin: " + origin + "\tCurrent url:" + request.getRequestURL());

        // Only set CORS headers when origin is present and passes the safe-domain allowlist.
        // Null origin means same-origin or direct browser request — no CORS headers needed.
        if (origin != null) {
            if (SecurityUtil.checkURL(origin) == null) {
                logger.error("[-] Origin check error. " + "Origin: " + origin +
                        "\tCurrent url:" + request.getRequestURL());
                response.setStatus(response.SC_FORBIDDEN);
                response.getWriter().println("Invaid cors config by joychou.");
                return;
            }
            String allowedOrigin = matchAllowedOrigin(origin);
            if (allowedOrigin == null) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().println("Origin is not allowed.");
                return;
            }
            response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTION");
        }

        filterChain.doFilter(req, res);
    }

    @Override
    public void destroy() {

    }
}
