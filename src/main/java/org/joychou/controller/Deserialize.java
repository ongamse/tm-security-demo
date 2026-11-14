package org.joychou.controller;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
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
 * The rememberMe cookie carries Base64(JSON), parsed into a fixed data-only DTO.
 * Java object deserialization of request data is never performed.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** Maximum accepted size of the decoded cookie payload. */
    private static final int MAX_PAYLOAD_BYTES = 4096;

    /** No default typing is enabled, so only the fixed DTO type can ever be instantiated. */
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    /**
     * Data-only remember-me payload.
     */
    @JsonIgnoreProperties(ignoreUnknown = false)
    public static class RememberMeData {
        private String name;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    /**
     * Decode Base64 JSON into the fixed DTO. Throws IllegalArgumentException (bad Base64)
     * or IOException (bad JSON / unknown fields) on malformed input.
     */
    static RememberMeData parseRememberMe(String cookieValue) throws IOException {
        byte[] decoded = Base64.getDecoder().decode(cookieValue);
        if (decoded.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("rememberMe payload too large");
        }
        return MAPPER.readValue(new String(decoded, StandardCharsets.UTF_8), RememberMeData.class);
    }

    /**
     * Example cookie: rememberMe=base64({"name":"joychou"}) <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        try {
            parseRememberMe(cookie.getValue());
        } catch (IOException | IllegalArgumentException e) {
            logger.info("Invalid rememberMe cookie: " + e.getClass().getSimpleName());
            return "Invalid rememberMe cookie.";
        }

        return "Are u ok?";
    }

    /**
     * Same data-only parsing; malformed input is rejected with a generic message. <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        try {
            parseRememberMe(cookie.getValue());
        } catch (IOException | IllegalArgumentException e) {
            logger.info("Invalid rememberMe cookie: " + e.getClass().getSimpleName());
            return "Invalid rememberMe cookie.";
        }

        return "I'm very OK.";
    }

}
