package org.joychou.controller;

import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
 * Remember-me cookie handling.
 * <p>
 * The cookie no longer carries a native Java serialized object. It carries a plain
 * string (the remember-me user name) as {@code base64url(value) + "." + base64url(HMAC-SHA256(value))}.
 * The HMAC is verified (constant time) with a server-side secret before the value is used, and no
 * ObjectInputStream is involved, so request data can never reach Java deserialization.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Server-side HMAC key, supplied via env REMEMBER_ME_SECRET (property joychou.security.rememberme.secret).
     * When it is empty every cookie is rejected (fail closed).
     */
    @Value("${joychou.security.rememberme.secret:}")
    private String rememberMeSecret;

    /**
     * Verify the HMAC-SHA256 of a cookie value and return the authenticated plain-string payload,
     * or null if the cookie is malformed or not authentic.
     */
    private String verifyRememberMe(String cookieValue) {
        if (rememberMeSecret == null || rememberMeSecret.isEmpty() || cookieValue == null) {
            return null;
        }
        String[] parts = cookieValue.split("\\.", -1);
        if (parts.length != 2) {
            return null;
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[0]);
            byte[] signature = Base64.getUrlDecoder().decode(parts[1]);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(rememberMeSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(payload);

            if (!MessageDigest.isEqual(expected, signature)) {
                return null;
            }
            return new String(payload, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            logger.info("Invalid rememberMe cookie: " + e.getClass().getSimpleName());
            return null;
        }
    }

    /**
     * Cookie format: base64url(username) + "." + base64url(HMAC-SHA256(username)). <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        // Authenticate first; the payload is a plain string and is never deserialized as a Java object.
        String user = verifyRememberMe(cookie.getValue());
        if (user == null) {
            return "Invalid rememberMe cookie.";
        }

        return "Are u ok?";
    }

    /**
     * Same authenticated plain-string remember-me check (no Java deserialization of request data). <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        // Authenticate first; the payload is a plain string and is never deserialized as a Java object.
        String user = verifyRememberMe(cookie.getValue());
        if (user == null) {
            return "Invalid rememberMe cookie.";
        }

        return "I'm very OK.";
    }

}
