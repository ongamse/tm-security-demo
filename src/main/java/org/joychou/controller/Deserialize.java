package org.joychou.controller;

import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling. The cookie is NOT a Java-serialized object: it carries
 * Base64(payload) + "." + Base64(HMAC-SHA256(payload)), where payload is a plain UTF-8 string.
 * No Java deserialization is performed on request data.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String KEY_ENV = "JSC_REMEMBERME_KEY";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public ResponseEntity<String> rememberMeVul(HttpServletRequest request) {
        return handleRememberMe(request, "Are u ok?");
    }

    /**
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public ResponseEntity<String> rememberMeBlackClassCheck(HttpServletRequest request) {
        return handleRememberMe(request, "I'm very OK.");
    }

    private ResponseEntity<String> handleRememberMe(HttpServletRequest request, String okMessage) {
        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return ResponseEntity.ok("No rememberMe cookie. Right?");
        }

        String key = System.getenv(KEY_ENV);
        if (key == null || key.isEmpty()) {
            logger.warn("rememberMe verification key is not configured");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("rememberMe is not available.");
        }

        String payload = verifyAndExtract(cookie.getValue(), key);
        if (payload == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid rememberMe cookie.");
        }

        return ResponseEntity.ok(okMessage);
    }

    /**
     * Verify the HMAC of "Base64(payload).Base64(mac)" and return the payload as a String,
     * or null when the value is malformed or the signature does not match.
     */
    private static String verifyAndExtract(String cookieValue, String key) {
        if (cookieValue == null) {
            return null;
        }
        int dot = cookieValue.indexOf('.');
        if (dot <= 0 || dot == cookieValue.length() - 1 || cookieValue.indexOf('.', dot + 1) != -1) {
            return null;
        }

        try {
            byte[] payload = Base64.getDecoder().decode(cookieValue.substring(0, dot));
            byte[] givenMac = Base64.getDecoder().decode(cookieValue.substring(dot + 1));

            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] expectedMac = mac.doFinal(payload);

            if (!MessageDigest.isEqual(expectedMac, givenMac)) {
                return null;
            }
            return new String(payload, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return null;
        }
    }

}
