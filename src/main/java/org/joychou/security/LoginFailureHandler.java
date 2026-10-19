package org.joychou.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



public class LoginFailureHandler implements AuthenticationFailureHandler {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException exception)
                                        throws ServletException, IOException {

        String username = request.getParameter("username");
        // Sanitize user-controlled values before logging to prevent log injection
        String safeUsername = SecurityUtil.sanitizeCRLF(username != null ? username.replaceAll("[^a-zA-Z0-9@._\\-]", "") : "");
        String safeUrl = SecurityUtil.sanitizeCRLF(request.getRequestURL().toString());

        logger.info("Login failed. {} username: {}", safeUrl, safeUsername);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":1, \"message\":\"Login failed.\"}");
    }

}
