package org.joychou.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InvalidClassException;
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

    private static final int MAX_REMEMBER_ME_BYTES = 4096;

    private static final ObjectMapper REMEMBER_ME_MAPPER = new ObjectMapper();

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
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        // Data-only parsing: the cookie is never turned into arbitrary Java objects.
        parseRememberMe(decoded);

        return "Are u ok?";
    }

    /**
     * Check deserialize class using allow list. <br>
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

        try {
            parseRememberMe(decoded);
        } catch (InvalidClassException e) {
            logger.info(e.toString());
            return e.toString();
        }

        return "I'm very OK.";
    }

    /**
     * Parse the decoded rememberMe cookie as plain JSON data. Jackson default typing is not
     * enabled, so no class names from the payload are ever instantiated; the result is a
     * generic JsonNode tree only.
     */
    private static JsonNode parseRememberMe(byte[] decoded) throws IOException {
        if (decoded.length > MAX_REMEMBER_ME_BYTES) {
            throw new InvalidClassException("rememberMe cookie too large");
        }
        try {
            return REMEMBER_ME_MAPPER.readTree(decoded);
        } catch (JsonProcessingException e) {
            throw new InvalidClassException("Invalid rememberMe cookie format");
        }
    }

}
