package org.joychou.controller;

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
    @RequestMapping("/reflect")
    @ResponseBody
    public static String reflect(String xss) {
        return xss == null ? "" : HtmlUtils.htmlEscape(xss);
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
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(3600);
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
        return xss == null ? "" : HtmlUtils.htmlEscape(xss);
    }

    /**
     * safe Code.
     * http://localhost:8080/xss/safe
     */
    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return xss == null ? "" : HtmlUtils.htmlEscape(xss);
    }
}
