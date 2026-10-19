package org.joychou.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Csrf access denied page.
 *
 * @author JoyChou
 */
public class CsrfAccessDeniedHandler implements AccessDeniedHandler {

    protected final Logger logger= LoggerFactory.getLogger(this.getClass());

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        // Sanitize user-controlled values before logging to prevent log injection
        String safeUrl = SecurityUtil.sanitizeCRLF(request.getRequestURL().toString());
        String safeQuery = SecurityUtil.sanitizeCRLF(request.getQueryString());
        String safeReferer = SecurityUtil.sanitizeCRLF(request.getHeader("referer"));

        logger.info("[-] URL: {}?{}\tReferer: {}", safeUrl, safeQuery, safeReferer);

        response.setContentType(MediaType.TEXT_HTML_VALUE); // content-type: text/html
        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403 forbidden
        response.getWriter().write("403 forbidden by JoyChou.");  // response contents
    }

}

