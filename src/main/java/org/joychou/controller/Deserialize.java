package org.joychou.controller;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.joychou.dao.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling.
 *
 * The cookie is NOT Java-serialized data. It is "base64url(json) . base64url(HMAC-SHA256(json))":
 * the signature is verified (constant time, key from the environment) before the payload is parsed,
 * and the payload is bound as JSON into the fixed {@link User} DTO (no polymorphic typing, no native
 * Java deserialization), failing closed on any mismatch.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Max accepted cookie value length (a browser cookie is at most ~4KB anyway).
    private static final int MAX_COOKIE_LENGTH = 4096;

    // Fixed-type JSON binding: no default typing, unknown properties rejected.
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    // HMAC key supplied at runtime via the REMEMBER_ME_HMAC_KEY environment variable. Empty => reject all.
    @Value("${joychou.security.rememberme.hmac.key:}")
    private String hmacKey;

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        User user = readSignedUser(cookie.getValue());
        if (user == null) {
            return "Invalid rememberMe cookie.";
        }

        return "Are u ok?";
    }

    /**
     * Signature-verified, fixed-type (JSON) rememberMe check. <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        User user = readSignedUser(cookie.getValue());
        if (user == null) {
            return "Invalid rememberMe cookie.";
        }

        return "I'm very OK.";
    }

    /**
     * Verify the HMAC-SHA256 signature first, then bind the JSON payload to {@link User}.
     * Returns null (fail closed) on a missing key, malformed value, bad signature or bad payload.
     */
    private User readSignedUser(String cookieValue) {
        if (hmacKey == null || hmacKey.isEmpty()
                || cookieValue == null || cookieValue.length() > MAX_COOKIE_LENGTH) {
            return null;
        }

        int dot = cookieValue.indexOf('.');
        if (dot <= 0 || dot != cookieValue.lastIndexOf('.') || dot == cookieValue.length() - 1) {
            return null;
        }

        try {
            byte[] payload = Base64.getUrlDecoder().decode(cookieValue.substring(0, dot));
            byte[] signature = Base64.getUrlDecoder().decode(cookieValue.substring(dot + 1));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(payload);

            // Constant-time compare; reject before the payload is parsed.
            if (!MessageDigest.isEqual(expected, signature)) {
                logger.info("rememberMe signature mismatch");
                return null;
            }

            return MAPPER.readValue(payload, User.class);
        } catch (IllegalArgumentException | GeneralSecurityException | IOException e) {
            logger.info("Invalid rememberMe cookie: " + e.getClass().getSimpleName());
            return null;
        }
    }

}
