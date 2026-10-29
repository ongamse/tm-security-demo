package org.joychou.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import java.util.Map;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling.
 *
 * The cookie value is untrusted. It is never passed to a native (Java serialization) deserializer, which
 * allows gadget-chain RCE (e.g. Commons-Collections). It is treated as a Base64-encoded JSON document and
 * bound to a plain data structure; Jackson default typing is not enabled, so no class names from the
 * request are ever resolved or instantiated.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** Upper bound for the decoded cookie payload. */
    private static final int MAX_PAYLOAD_BYTES = 4096;

    // No default typing / polymorphic types: JSON maps only to Map/List/String/Number/Boolean/null.
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Decodes the rememberMe cookie (Base64 of a small JSON object) into a plain Map.
     *
     * @throws IllegalArgumentException if the cookie is not valid Base64 or exceeds the size limit
     * @throws JsonProcessingException  if the payload is not a JSON object
     */
    private static Map<?, ?> readRememberMe(String cookieValue) throws IOException {
        if (cookieValue.length() > (MAX_PAYLOAD_BYTES / 3 + 1) * 4) {
            throw new IllegalArgumentException("rememberMe cookie too large");
        }
        byte[] decoded = Base64.getDecoder().decode(cookieValue);
        if (decoded.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("rememberMe cookie too large");
        }
        return MAPPER.readValue(decoded, Map.class);
    }

    /**
     * Base64 of a JSON object, e.g. {"name":"world"} <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) throws IOException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        readRememberMe(cookie.getValue());

        return "Are u ok?";
    }

    /**
     * Same data-only parsing as above, but invalid payloads are reported to the caller instead of failing. <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) throws IOException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        try {
            readRememberMe(cookie.getValue());
        } catch (JsonProcessingException e) {
            logger.info("Invalid rememberMe payload: {}", e.getOriginalMessage());
            return "Invalid rememberMe payload";
        } catch (IllegalArgumentException e) {
            logger.info("Invalid rememberMe cookie: {}", e.getMessage());
            return "Invalid rememberMe cookie";
        }

        return "I'm very OK.";
    }

}
