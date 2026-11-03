package org.joychou.controller;

import org.joychou.config.Constants;
import org.joychou.security.AntObjectInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * Deserialize RCE using Commons-Collections gadget.
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final int MAX_COOKIE_LENGTH = 8192;

    /**
     * java -jar ysoserial.jar CommonsCollections5 "open -a Calculator" | base64 <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request)
            throws IOException, ClassNotFoundException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        byte[] decoded = decodeCookie(cookie.getValue());
        if (decoded == null) {
            return "Invalid rememberMe cookie.";
        }

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);
        // Allowlist-based deserialization: unexpected classes are rejected (fail closed).
        try (AntObjectInputStream in = new AntObjectInputStream(bytes)) {
            in.readObject();
        } catch (IOException | ClassNotFoundException | RuntimeException e) {
            logger.info("Rejected rememberMe cookie: {}", e.getClass().getSimpleName());
            return "Invalid rememberMe cookie.";
        }

        return "Are u ok?";
    }

    /**
     * Check deserialize class using black list. <br>
     * Or update commons-collections to 3.2.2 or above.Serialization support for org.apache.commons.collections.functors.InvokerTransformer is disabled for security reasons.To enable it set system property 'org.apache.commons.collections.enableUnsafeSerialization' to 'true',but you must ensure that your application does not de-serialize objects from untrusted sources.<br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request)
            throws IOException, ClassNotFoundException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }
        byte[] decoded = decodeCookie(cookie.getValue());
        if (decoded == null) {
            return "Invalid rememberMe cookie.";
        }

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);

        // Allowlist-based deserialization (resolveClass throws InvalidClassException for unexpected classes).
        try (AntObjectInputStream in = new AntObjectInputStream(bytes)) {
            in.readObject();
        } catch (IOException | ClassNotFoundException | RuntimeException e) {
            logger.info("Rejected rememberMe cookie: {}", e.getClass().getSimpleName());
            return "Invalid rememberMe cookie.";
        }

        return "I'm very OK.";
    }

    /**
     * Base64-decode the cookie value, enforcing a size limit before deserialization.
     *
     * @return decoded bytes, or null when the value is oversized or not valid Base64
     */
    private static byte[] decodeCookie(String value) {
        if (value == null || value.length() > MAX_COOKIE_LENGTH) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

}
