package org.joychou.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

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

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final int MAX_COOKIE_DECODED_BYTES = 4096;

    private static final int MAX_COOKIE_ENCODED_LENGTH = 4 * ((MAX_COOKIE_DECODED_BYTES + 2) / 3);

    private static final String INVALID_COOKIE = "Invalid rememberMe cookie.";

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

        if (null == parseRememberMe(cookie)) {
            return INVALID_COOKIE;
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
        if (null == parseRememberMe(cookie)) {
            return INVALID_COOKIE;
        }

        return "I'm very OK.";
    }

    private static Map<String, String> parseRememberMe(Cookie cookie) {
        String value = cookie.getValue();
        if (value == null || value.length() > MAX_COOKIE_ENCODED_LENGTH) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length > MAX_COOKIE_DECODED_BYTES) {
                return null;
            }
            String json = new String(decoded, StandardCharsets.UTF_8);
            return MAPPER.readValue(json, new TypeReference<Map<String, String>>() { });
        } catch (IllegalArgumentException | IOException e) {
            return null;
        }
    }

}
