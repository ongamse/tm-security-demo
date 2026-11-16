package org.joychou.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling. The cookie is parsed as a typed JSON object (Base64 encoded);
 * Java native deserialization of request data is intentionally not performed.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** Upper bound for the decoded rememberMe payload. */
    private static final int MAX_PAYLOAD_BYTES = 4096;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Typed DTO for the rememberMe cookie payload. */
    public static class RememberMe {
        private String name;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    /**
     * Decode and parse the rememberMe cookie into a typed DTO.
     *
     * @return the parsed DTO, or null when the cookie value is malformed or too large
     */
    private RememberMe parseRememberMe(String cookieValue) {
        // Base64 expands by 4/3; reject oversized input before decoding.
        if (cookieValue.length() > (MAX_PAYLOAD_BYTES / 3 + 1) * 4) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(cookieValue);
            if (decoded.length > MAX_PAYLOAD_BYTES) {
                return null;
            }
            return MAPPER.readValue(decoded, RememberMe.class);
        } catch (IllegalArgumentException e) {
            logger.info("Invalid rememberMe base64: " + e.getMessage());
            return null;
        } catch (IOException e) {
            logger.info("Invalid rememberMe payload: " + e.getMessage());
            return null;
        }
    }

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        if (parseRememberMe(cookie.getValue()) == null) {
            return "Invalid rememberMe cookie.";
        }

        return "Are u ok?";
    }

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        if (parseRememberMe(cookie.getValue()) == null) {
            return "Invalid rememberMe cookie.";
        }

        return "I'm very OK.";
    }

}
