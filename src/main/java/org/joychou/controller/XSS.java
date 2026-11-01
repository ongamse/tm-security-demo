package org.joychou.controller;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;


/**
 * @author JoyChou @2018-01-02
 */
@Controller
@RequestMapping("/xss")
public class XSS {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * ReflectXSS endpoint. The request value is never written back into the response body;
     * a JSON summary containing only a numeric length is returned.
     * http://localhost:8080/xss/reflect?xss=value
     *
     * @param xss untrusted string
     */
    @RequestMapping(value = "/reflect", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ResponseBody
    public static Map<String, Object> reflect(String xss, HttpServletResponse response) {
        response.setHeader("X-Content-Type-Options", "nosniff");
        return Collections.<String, Object>singletonMap("length", xss == null ? 0 : xss.length());
    }

    /**
     * Vul Code.
     * StoredXSS Step1
     * http://localhost:8080/xss/stored/store?xss=<script>alert(1)</script>
     *
     * @param xss unescape string
     */
    @RequestMapping("/stored/store")
    @ResponseBody
    public String store(String xss, HttpServletResponse response) {
        // The request value is never placed in the cookie; a server-generated random token is used.
        Cookie cookie = new Cookie("xss", newToken());
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        return "Set param into cookie";
    }

    private static String newToken() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX[(b >> 4) & 0x0f]).append(HEX[b & 0x0f]);
        }
        return sb.toString();
    }

    /**
     * StoredXSS Step2. The stored cookie value is not written back into the response body;
     * a JSON summary containing only a numeric length is returned.
     * http://localhost:8080/xss/stored/show
     *
     * @param xss stored string
     */
    @RequestMapping(value = "/stored/show", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ResponseBody
    public Map<String, Object> show(@CookieValue("xss") String xss, HttpServletResponse response) {
        response.setHeader("X-Content-Type-Options", "nosniff");
        return Collections.<String, Object>singletonMap("length", xss == null ? 0 : xss.length());
    }

    /**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping(value = "/safe", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ResponseBody
    public static Map<String, Object> safe(String xss) {
        return Collections.<String, Object>singletonMap("length", xss == null ? 0 : xss.length());
    }
}
