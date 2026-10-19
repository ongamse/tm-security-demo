package org.joychou.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.joychou.security.SecurityUtil.sanitizeForLog;
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

        logger.info("Login failed. " + sanitizeForLog(request.getRequestURL().toString()) +
                " username: " + sanitizeForLog(request.getParameter("username")) +
                " password: [REDACTED]" );

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":1, \"message\":\"Login failed.\"}");
    }

}
