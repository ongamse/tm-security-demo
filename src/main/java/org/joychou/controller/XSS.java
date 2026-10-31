package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;


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
    @RequestMapping(value = "/reflect", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public static ResponseEntity<String> reflect(String xss) {
        return plainText(encode(xss));
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
        // Reject CR, LF and any other control character, then URL-encode what goes into Set-Cookie.
        if (!SecurityUtil.isValidHeaderValue(xss)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "Invalid xss parameter";
        }
        Cookie cookie = new Cookie("xss", SecurityUtil.encodeHeaderValue(xss));
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
    @RequestMapping(value = "/stored/show", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public ResponseEntity<String> show(@CookieValue("xss") String xss) {
        return plainText(encode(xss));
    }

    /**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping(value = "/safe", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public static ResponseEntity<String> safe(String xss) {
        return plainText(encode(xss));
    }

    /**
     * Echoed user data is never served as HTML: explicit text/plain plus nosniff.
     */
    private static ResponseEntity<String> plainText(String body) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body(body);
    }

    private static String encode(String origin) {
        return HtmlUtils.htmlEscape(origin);
    }
}
