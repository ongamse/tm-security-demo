package org.joychou.controller;

import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

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

    /** Maximum accepted decoded payload size in bytes. */
    private static final int MAX_PAYLOAD_BYTES = 4096;
    /** Maximum accepted Base64 cookie length (4/3 of the payload limit, rounded up). */
    private static final int MAX_COOKIE_CHARS = 5464;

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

        String rememberMe = cookie.getValue();
        if (rememberMe == null || rememberMe.length() > MAX_COOKIE_CHARS) {
            return "rememberMe cookie too large.";
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(rememberMe);
        } catch (IllegalArgumentException e) {
            return "Invalid rememberMe cookie.";
        }
        if (decoded.length > MAX_PAYLOAD_BYTES) {
            return "rememberMe payload too large.";
        }

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);

        // Class allowlist enforced by AllowlistObjectInputStream.resolveClass (defined in this file).
        try (AllowlistObjectInputStream in = new AllowlistObjectInputStream(bytes)) {
            in.readObject();
        } catch (InvalidClassException e) {
            logger.info(e.toString());
            return "Invalid rememberMe payload.";
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
        String rememberMe = cookie.getValue();
        if (rememberMe == null || rememberMe.length() > MAX_COOKIE_CHARS) {
            return "rememberMe cookie too large.";
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(rememberMe);
        } catch (IllegalArgumentException e) {
            return "Invalid rememberMe cookie.";
        }
        if (decoded.length > MAX_PAYLOAD_BYTES) {
            return "rememberMe payload too large.";
        }

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);

        // Class allowlist enforced by AllowlistObjectInputStream.resolveClass (defined in this file).
        try (AllowlistObjectInputStream in = new AllowlistObjectInputStream(bytes)) {
            in.readObject();  // throws InvalidClassException for non-allowlisted classes
        } catch (InvalidClassException e) {
            logger.info(e.toString());
            return "Invalid rememberMe payload.";
        }

        return "I'm very OK.";
    }

    /**
     * ObjectInputStream that only resolves explicitly allowlisted classes (fail closed).
     * Dynamic proxies are rejected as well.
     */
    private static final class AllowlistObjectInputStream extends ObjectInputStream {

        private static final Set<String> ALLOWED_CLASSES = Collections.unmodifiableSet(
                new HashSet<String>(Arrays.asList("org.joychou.security.AntObjectInputStream$MyObject")));

        AllowlistObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!ALLOWED_CLASSES.contains(desc.getName())) {
                throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
            }
            return super.resolveClass(desc);
        }

        @Override
        protected Class<?> resolveProxyClass(String[] interfaces)
                throws IOException, ClassNotFoundException {
            throw new InvalidClassException("Unauthorized deserialization attempt (proxy class)");
        }
    }

}
