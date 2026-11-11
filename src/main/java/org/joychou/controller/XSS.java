package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/**
 * @author JoyChou @2018-01-02
 */
@Controller
@RequestMapping("/xss")
public class XSS {

    /**
     * Closed set of values that may be stored in the demo "xss" cookie.
     */
    private static final List<String> ALLOWED_COOKIE_VALUES = Collections.unmodifiableList(
            Arrays.asList("test", "hello", "joychou"));

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
        return WebUtils.htmlSafeRebuild(xss);
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
        // Cookie value is a constant from the allowlist, never the raw request value.
        String allowed = SecurityUtil.allowedConstant(xss, ALLOWED_COOKIE_VALUES);
        if (allowed != null) {
            Cookie cookie = new Cookie("xss", allowed);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);
        }
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
        return WebUtils.htmlSafeRebuild(xss);
    }

    /**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return WebUtils.htmlSafeRebuild(xss);
    }
}
