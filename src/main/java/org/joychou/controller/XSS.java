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
    @RequestMapping(value = "/safe", produces = "text/plain;charset=UTF-8")
    public ResponseEntity<String> safe(String xss) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body(encode(xss));
    }

    /**
     * Build a new string in which every character outside [A-Za-z0-9 ._-]
     * is replaced by a numeric character reference.
     */
    private static String encode(String origin) {
        if (origin == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(origin.length() * 2);
        int i = 0;
        while (i < origin.length()) {
            int cp = origin.codePointAt(i);
            i += Character.charCount(cp);
            boolean letter = (cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z');
            boolean digit = cp >= '0' && cp <= '9';
            if (letter || digit) {
                sb.append((char) cp);
            } else if (cp == ' ' || cp == '.' || cp == '_' || cp == '-') {
                sb.append((char) cp);
            } else {
                sb.append("&#").append(cp).append(';');
            }
        }
        return sb.toString();
    }
}
