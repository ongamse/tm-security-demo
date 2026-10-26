package org.joychou.filter;


import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.joychou.security.SecurityUtil;
import static org.joychou.security.SecurityUtil.sanitizeLogOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 推荐使用该全局方案修复Cors跨域漏洞，因为可以校验一级域名。
 *
 * @author JoyChou @ 2019.12.19
 */
@WebFilter(filterName = "OriginFilter", urlPatterns = "/cors/sec/originFilter")
public class OriginFilter implements Filter {

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
        logger.info("[+] Origin: " + sanitizeLogOutput(origin) + " Current url:" + sanitizeLogOutput(request.getRequestURL().toString()));

        // Only set CORS headers when origin is present and passes the domain allowlist
        if (origin != null) {
            String validatedOrigin = SecurityUtil.checkURL(origin);
            if (validatedOrigin == null) {
                logger.error("[-] Origin check error. " + "Origin: " + sanitizeLogOutput(origin) +
                        " Current url:" + sanitizeLogOutput(request.getRequestURL().toString()));
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().println("Invalid cors config by joychou.");
                return;
            }
            response.setHeader("Access-Control-Allow-Origin", SecurityUtil.sanitizeHeaderValue(validatedOrigin));
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTION");
        }
        // If origin is null, it's a same-origin request — no CORS headers needed.

        filterChain.doFilter(req, res);
    }

    @Override
    public void destroy() {

    }
}
