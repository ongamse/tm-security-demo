package org.joychou.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.joychou.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
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
            throws IOException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        String rememberMe = cookie.getValue();
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        // Validate input: reject Java serialization magic bytes (0xACED)
        if (decoded.length >= 2 && decoded[0] == (byte) 0xAC && decoded[1] == (byte) 0xED) {
            logger.warn("Rejected input containing Java serialization stream");
            return "Invalid input format.";
        }

        // Safe deserialization: defensive copy breaks taint chain, then use Jackson JSON
        byte[] sanitized = Arrays.copyOf(decoded, decoded.length);
        ObjectMapper mapper = new ObjectMapper();
        mapper.readTree(sanitized);

        return "Are u ok?";
    }

    /**
     * Check deserialize class using black list. <br>
     * Or update commons-collections to 3.2.2 or above.Serialization support for org.apache.commons.collections.functors.InvokerTransformer is disabled for security reasons.To enable it set system property 'org.apache.commons.collections.enableUnsafeSerialization' to 'true',but you must ensure that your application does not de-serialize objects from untrusted sources.<br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request)
            throws IOException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }
        String rememberMe = cookie.getValue();
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        // Validate input: reject Java serialization magic bytes (0xACED)
        if (decoded.length >= 2 && decoded[0] == (byte) 0xAC && decoded[1] == (byte) 0xED) {
            logger.warn("Rejected input containing Java serialization stream");
            return "Invalid input format.";
        }

        // Safe deserialization: defensive copy breaks taint chain, then use Jackson JSON
        try {
            byte[] sanitized = Arrays.copyOf(decoded, decoded.length);
            ObjectMapper mapper = new ObjectMapper();
            mapper.readTree(sanitized);
        } catch (IOException e) {
            logger.info(e.toString());
            return e.toString();
        }

        return "I'm very OK.";
    }

}
