package org.joychou.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.joychou.dao.User;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * RememberMe cookie endpoints — parse cookie payload as JSON (no Java deserialization).
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * ObjectMapper with default configuration is safe: no polymorphic type handling,
     * no default typing. Only known POJO fields are bound.
     */
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Secure rememberMe endpoint — parses cookie value as Base64-encoded JSON
     * into a known safe type (User) instead of using Java deserialization.
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        String rememberMe = cookie.getValue();
        try {
            byte[] decoded = Base64.getDecoder().decode(rememberMe);
            String json = new String(decoded, StandardCharsets.UTF_8);
            // Parse as JSON into a known, concrete type — no Java deserialization
            User user = objectMapper.readValue(json, User.class);
            logger.info("Parsed rememberMe cookie for user: {}", SecurityUtil.sanitizeForLog(user.getUsername()));
        } catch (IllegalArgumentException e) {
            logger.info("Invalid base64 in rememberMe cookie: {}", e.getMessage());
            return "Invalid cookie encoding.";
        } catch (IOException e) {
            logger.info("Invalid JSON in rememberMe cookie: {}", e.getMessage());
            return "Invalid cookie format.";
        }

        return "Are u ok?";
    }

    /**
     * Secure rememberMe endpoint — same JSON-based parsing approach.
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }
        String rememberMe = cookie.getValue();
        try {
            byte[] decoded = Base64.getDecoder().decode(rememberMe);
            String json = new String(decoded, StandardCharsets.UTF_8);
            // Parse as JSON into a known, concrete type — no Java deserialization
            User user = objectMapper.readValue(json, User.class);
            logger.info("Parsed rememberMe cookie for user: {}", SecurityUtil.sanitizeForLog(user.getUsername()));
        } catch (IllegalArgumentException e) {
            logger.info("Invalid base64 in rememberMe cookie: {}", e.getMessage());
            return "Invalid cookie encoding.";
        } catch (IOException e) {
            logger.info("Invalid JSON in rememberMe cookie: {}", e.getMessage());
            return "Invalid cookie format.";
        }

        return "I'm very OK.";
    }

}
