package org.joychou.controller;

import org.joychou.config.Constants;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.dao.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
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

        if (readRememberMe(cookie.getValue()) == null) {
            return INVALID_REMEMBER_ME;
        }

        return "Are u ok?";
    }

    private static final String INVALID_REMEMBER_ME = "Invalid rememberMe cookie.";

    // The rememberMe cookie is Base64(JSON) of a User; the JSON mapper has default typing off, so
    // the payload can only populate the User bean and can never select an arbitrary class.
    private static final int MAX_REMEMBER_ME_BYTES = 4096;
    private static final ObjectMapper REMEMBER_ME_MAPPER = new ObjectMapper();

    /**
     * Decode the rememberMe cookie into a User. No Java native deserialization is used.
     *
     * @return the parsed User, or null when the cookie is not a valid Base64 JSON User
     */
    private User readRememberMe(String cookieValue) {
        try {
            byte[] decoded = Base64.getDecoder().decode(cookieValue);
            if (decoded.length == 0 || decoded.length > MAX_REMEMBER_ME_BYTES) {
                return null;
            }
            return REMEMBER_ME_MAPPER.readValue(decoded, User.class);
        } catch (IllegalArgumentException | IOException e) {
            logger.info("Rejected rememberMe cookie: " + e.getClass().getSimpleName());
            return null;
        }
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
        if (readRememberMe(cookie.getValue()) == null) {
            return INVALID_REMEMBER_ME;
        }

        return "I'm very OK.";
    }

}
