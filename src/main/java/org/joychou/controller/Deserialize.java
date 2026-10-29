package org.joychou.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling. The cookie is a signed, data-only JSON document
 * (format: base64(payload).base64(hmac-sha256)); it is never Java-deserialized.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String KEY_NAME = "JSC_REMEMBERME_KEY";
    private static final int MAX_COOKIE_BYTES = 4096;
    private static final String ERROR_MESSAGE = "Invalid rememberMe cookie.";

    // Plain ObjectMapper: no default typing, no polymorphic types.
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        if (!parseSignedCookie(cookie.getValue())) {
            return ERROR_MESSAGE;
        }

        return "Are u ok?";
    }

    /**
     * Verified, data-only rememberMe parsing. <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        if (!parseSignedCookie(cookie.getValue())) {
            return ERROR_MESSAGE;
        }

        return "I'm very OK.";
    }

    /**
     * Verify the HMAC-SHA256 signature and parse the payload as plain JSON.
     *
     * @return true only when the cookie is well-formed, signed with the configured key and valid JSON
     */
    private boolean parseSignedCookie(String value) {
        try {
            String key = System.getenv(KEY_NAME);
            if (key == null || key.isEmpty()) {
                key = System.getProperty(KEY_NAME);
            }
            if (key == null || key.isEmpty()) {
                logger.warn("{} is not configured; rejecting rememberMe cookie", KEY_NAME);
                return false;
            }

            if (value == null || value.length() > MAX_COOKIE_BYTES * 2) {
                return false;
            }
            String[] parts = value.split("\\.", -1);
            if (parts.length != 2) {
                return false;
            }

            byte[] payload = Base64.getDecoder().decode(parts[0]);
            byte[] signature = Base64.getDecoder().decode(parts[1]);
            if (payload.length == 0 || payload.length > MAX_COOKIE_BYTES) {
                return false;
            }

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(payload);
            if (!MessageDigest.isEqual(expected, signature)) {
                return false;
            }

            Map<String, Object> data = MAPPER.readValue(payload, new TypeReference<Map<String, Object>>() {
            });
            return data != null;
        } catch (Exception e) {
            logger.info("rememberMe cookie rejected");
            return false;
        }
    }

}
