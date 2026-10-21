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
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.Base64;
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

    /**
     * Allowlist of classes permitted for deserialization.
     * Only domain types that are expected in serialized cookie data are allowed.
     */
    private static final Set<String> ALLOWED_DESERIALIZE_CLASSES = new HashSet<>(Arrays.asList(
            "org.joychou.security.AntObjectInputStream$MyObject",
            "org.joychou.dao.User",
            "java.lang.String",
            "java.lang.Number",
            "java.lang.Integer",
            "java.lang.Long",
            "java.util.ArrayList",
            "java.util.HashMap"
    ));

    /**
     * java -jar ysoserial.jar CommonsCollections5 "open -a Calculator" | base64 <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        String rememberMe = cookie.getValue();
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(rememberMe);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid base64 in rememberMe cookie: {}", e.getMessage());
            return "Invalid cookie encoding.";
        }

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);
        try {
            ObjectInputStream in = new ObjectInputStream(bytes) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc)
                        throws IOException, ClassNotFoundException {
                    if (!ALLOWED_DESERIALIZE_CLASSES.contains(desc.getName())) {
                        throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
                    }
                    return super.resolveClass(desc);
                }
            };
            in.readObject();
            in.close();
        } catch (InvalidClassException e) {
            logger.error("Blocked deserialization of unauthorized class: {}", e.getMessage());
            return "Deserialization blocked.";
        } catch (ClassNotFoundException | IOException e) {
            logger.error("Deserialization error: {}", e.getMessage());
            return "Deserialization error.";
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
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);

        try {
            ObjectInputStream in = new ObjectInputStream(bytes) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc)
                        throws IOException, ClassNotFoundException {
                    if (!ALLOWED_DESERIALIZE_CLASSES.contains(desc.getName())) {
                        throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
                    }
                    return super.resolveClass(desc);
                }
            };
            in.readObject();
            in.close();
        } catch (InvalidClassException e) {
            logger.info(e.toString());
            return e.toString();
        }

        return "I'm very OK.";
    }

}
