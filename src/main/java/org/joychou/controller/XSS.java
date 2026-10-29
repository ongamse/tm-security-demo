package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.joychou.security.SecurityUtil;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;


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
    @RequestMapping(value = "/reflect", produces = "text/plain;charset=UTF-8")
    public ResponseEntity<String> reflect(String xss) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body(HtmlUtils.htmlEscape(xss == null ? "" : xss, "UTF-8"));
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
    public String store(String xss, HttpServletResponse response) throws UnsupportedEncodingException {
        // Reject CR/LF and other control characters (also url-encoded) to prevent header injection.
        if (xss != null && SecurityUtil.headerFilter(xss) == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "Bad request";
        }
        String safe = SecurityUtil.toHeaderSafe(xss);
        Cookie cookie = new Cookie("xss", URLEncoder.encode(safe, "UTF-8"));
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
    @RequestMapping(value = "/stored/show", produces = "text/plain;charset=UTF-8")
    public ResponseEntity<String> show(@CookieValue("xss") String xssCookie) throws UnsupportedEncodingException {
        String xss = xssCookie == null ? null : URLDecoder.decode(xssCookie, "UTF-8");
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body(HtmlUtils.htmlEscape(xss == null ? "" : xss, "UTF-8"));
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
