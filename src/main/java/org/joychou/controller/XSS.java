package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Map;


/**
 * @author JoyChou @2018-01-02
 */
@Controller
@RequestMapping("/xss")
public class XSS {

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
        Cookie cookie = new Cookie("xss", xss);
        response.addCookie(cookie);
        return "Set param into cookie";
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
    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return encode(xss);
    }

    private static String encode(String origin) {
        origin = StringUtils.replace(origin, "&", "&amp;");
        origin = StringUtils.replace(origin, "<", "&lt;");
        origin = StringUtils.replace(origin, ">", "&gt;");
        origin = StringUtils.replace(origin, "\"", "&quot;");
        origin = StringUtils.replace(origin, "'", "&#x27;");
        origin = StringUtils.replace(origin, "/", "&#x2F;");
        return origin;
    }
}
