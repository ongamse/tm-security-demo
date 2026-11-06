package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


/**
 * @author JoyChou @2018-01-02
 */
@Controller
@RequestMapping("/xss")
public class XSS {

    /**
     * Vuln Code.
     * ReflectXSS
     * http://localhost:8080/xss/reflect?xss=<script>alert(1)</script>
     *
     * @param xss unescape string
     */
    @RequestMapping("/reflect")
    @ResponseBody
    public static String reflect(String xss) {
        return HtmlUtils.htmlEscape(xss);
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
        // Cookie value is rebuilt from a constant alphabet (Base64url, no padding)
        // so CR/LF and other reserved characters can never reach the Set-Cookie header
        Cookie cookie = new Cookie("xss", toCookieToken(xss == null ? "" : xss));
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        return "Set param into cookie";
    }

    /**
     * Vul Code.
     * StoredXSS Step2
     * http://localhost:8080/xss/stored/show
     *
     * @param xss unescape string
     */
    @RequestMapping("/stored/show")
    @ResponseBody
    public String show(@CookieValue("xss") String xss) {
        String decoded;
        try {
            decoded = new String(Base64.getUrlDecoder().decode(xss), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "Invalid cookie value";
        }
        return HtmlUtils.htmlEscape(decoded);
    }

    private static final String TOKEN_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /**
     * Base64url-encode (no padding) the UTF-8 bytes of the value, then copy it char by char
     * from a constant alphabet, dropping anything outside [A-Za-z0-9_-].
     */
    private static String toCookieToken(String value) {
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder token = new StringBuilder(encoded.length());
        for (int i = 0; i < encoded.length(); i++) {
            int idx = TOKEN_ALPHABET.indexOf(encoded.charAt(i));
            if (idx >= 0) {
                token.append(TOKEN_ALPHABET.charAt(idx));
            }
        }
        return token.toString();
    }

    /**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return HtmlUtils.htmlEscape(xss);
    }
}
