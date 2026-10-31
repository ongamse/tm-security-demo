package org.joychou.controller;

import org.joychou.config.Constants;
import org.joychou.security.RememberMeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

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
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        // No Java deserialization of the cookie: it is a signed plain-text token (username + HMAC).
        String username = RememberMeToken.verify(cookie.getValue());
        if (null == username) {
            logger.info("Invalid rememberMe token");
            return "Invalid rememberMe cookie.";
        }

        return "Are u ok?";
    }

    /**
     * Check deserialize class using allow list. <br>
     * Or update commons-collections to 3.2.2 or above.Serialization support for org.apache.commons.collections.functors.InvokerTransformer is disabled for security reasons.To enable it set system property 'org.apache.commons.collections.enableUnsafeSerialization' to 'true',but you must ensure that your application does not de-serialize objects from untrusted sources.<br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }
        // No Java deserialization of the cookie: it is a signed plain-text token (username + HMAC).
        String username = RememberMeToken.verify(cookie.getValue());
        if (null == username) {
            logger.info("Invalid rememberMe token");
            return "Invalid rememberMe cookie.";
        }

        return "I'm very OK.";
    }

}
