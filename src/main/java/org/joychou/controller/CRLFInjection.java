package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Java 1.7/1.8 no CRLF vulns (test in Java 1.7/1.8)
 *
 * @author JoyChou (joychou@joychou.org) @2018-01-03
 */
@Controller
@RequestMapping("/crlf")
public class CRLFInjection {

    @RequestMapping("/safecode")
    @ResponseBody
    public void crlf(HttpServletRequest request, HttpServletResponse response)
            throws UnsupportedEncodingException {
        String test1 = SecurityUtil.cRlfFilter(request.getParameter("test1"));
        if (test1 != null) {
            response.addHeader("test1", URLEncoder.encode(test1, StandardCharsets.UTF_8.name()));
        }
        String test2 = SecurityUtil.cRlfFilter(request.getParameter("test2"));
        if (test2 != null) {
            response.setHeader("test2", URLEncoder.encode(test2, StandardCharsets.UTF_8.name()));
        }
        String author = SecurityUtil.cRlfFilter(request.getParameter("test3"));
        // Cookie value is rebuilt from a constant alphabet so CR/LF and other
        // reserved characters can never reach the Set-Cookie header
        Cookie cookie = new Cookie("test3", toCookieToken(author));
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    /**
     * Base64url-encode (no padding) the UTF-8 bytes of the value, then copy it char by char,
     * dropping anything outside [A-Za-z0-9_-].
     */
    private static String toCookieToken(String value) {
        if (value == null) {
            return null;
        }
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder token = new StringBuilder(encoded.length());
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_') {
                token.append(c);
            }
        }
        return token.toString();
    }
}
