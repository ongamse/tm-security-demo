package org.joychou.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.joychou.security.SecurityUtil.sanitizeForLog;
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

        logger.info("[-] URL: " + sanitizeForLog(request.getRequestURL().toString()) + "?" + sanitizeForLog(request.getQueryString()) + "\t" +
                "Referer: " + sanitizeForLog(request.getHeader("referer")));

        response.setContentType(MediaType.TEXT_HTML_VALUE); // content-type: text/html
        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403 forbidden
        response.getWriter().write("403 forbidden by JoyChou.");  // response contents
    }

}

