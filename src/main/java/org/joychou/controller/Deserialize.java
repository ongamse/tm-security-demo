package org.joychou.controller;

import org.joychou.config.Constants;
import org.joychou.security.RememberMeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling. The cookie is an HMAC-SHA256 authenticated username
 * (see {@link RememberMeToken}); no Java native deserialization is performed on request data.
 * The signing key comes from property {@code jsc.remember-me.key} / env {@code JSC_REMEMBER_ME_KEY};
 * when it is unset or too short every cookie is rejected (HTTP 401).
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${jsc.remember-me.key:${JSC_REMEMBER_ME_KEY:}}")
    private String rememberMeKey;

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {
        if (null == getCookie(request, Constants.REMEMBER_ME_COOKIE)) {
            return "No rememberMe cookie. Right?";
        }
        requireValidCookie(request);
        return "Are u ok?";
    }

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {
        if (null == getCookie(request, Constants.REMEMBER_ME_COOKIE)) {
            return "No rememberMe cookie. Right?";
        }
        requireValidCookie(request);
        return "I'm very OK.";
    }

    private void requireValidCookie(HttpServletRequest request) {
        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        String user = RememberMeToken.verify(cookie == null ? null : cookie.getValue(), rememberMeKey);
        if (user == null) {
            logger.info("rejected rememberMe cookie");
            throw new InvalidRememberMeException();
        }
    }

    @ResponseStatus(value = HttpStatus.UNAUTHORIZED, reason = "invalid rememberMe cookie")
    static class InvalidRememberMeException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

}
