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
import java.util.Base64;

import static org.springframework.web.util.WebUtils.getCookie;

/**
 * rememberMe cookie handling (JSON bound to a fixed class; no Java native deserialization).
 *
 * @author JoyChou @2018-06-14
 */
@RestController
@RequestMapping("/deserialize")
public class Deserialize {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Default typing is never enabled on this mapper; unknown properties fail (Jackson default).
    private static final ObjectMapper REMEMBER_ME_MAPPER = new ObjectMapper();

    /**
     * Parse the rememberMe payload as plain JSON bound to a single fixed class.
     * No native Java deserialization and no polymorphic typing, so no gadget chain can be
     * instantiated. Unknown properties and malformed input are rejected.
     */
    private static RememberMe parseRememberMe(byte[] decoded) throws IOException {
        return REMEMBER_ME_MAPPER.readValue(decoded, RememberMe.class);
    }

    /** Plain data holder for the rememberMe cookie payload. */
    public static class RememberMe {
        private String name;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }
    }

    /**
     * echo '{"name":"joychou"}' | base64 <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/vuln">http://localhost:8080/deserialize/rememberMe/vuln</a>
     */
    @RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        String rememberMe = cookie.getValue();
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        try {
            parseRememberMe(decoded);
        } catch (IOException | IllegalArgumentException e) {
            logger.info(e.toString());
            return e.toString();
        }

        return "Are u ok?";
    }

    /**
     * Safe variant: the cookie is parsed as JSON into a fixed class instead of Java serialization. <br>
     * <a href="http://localhost:8080/deserialize/rememberMe/security">http://localhost:8080/deserialize/rememberMe/security</a>
     */
    @RequestMapping("/rememberMe/security")
    public String rememberMeBlackClassCheck(HttpServletRequest request) {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);

        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }
        String rememberMe = cookie.getValue();
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        try {
            parseRememberMe(decoded);
        } catch (IOException | IllegalArgumentException e) {
            logger.info(e.toString());
            return e.toString();
        }

        return "I'm very OK.";
    }

}
