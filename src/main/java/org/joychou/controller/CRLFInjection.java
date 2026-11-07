package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    public void crlf(HttpServletRequest request, HttpServletResponse response) {
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        if ((test1 != null && SecurityUtil.safeHeaderValue(test1) == null)
                || (test2 != null && SecurityUtil.safeHeaderValue(test2) == null)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        // strip CR, LF and other control characters from the exact values passed to the header calls
        String headerTest1 = test1 == null ? null : test1.replaceAll("[\\r\\n\\x00-\\x1F\\x7F]", "");
        String headerTest2 = test2 == null ? null : test2.replaceAll("[\\r\\n\\x00-\\x1F\\x7F]", "");
        response.addHeader("test1", headerTest1);
        response.setHeader("test2", headerTest2);
        String author = request.getParameter("test3");
        if (author == null) {
            author = "";
        }
        // reject CR, LF and other control characters, and over-long values
        if (author.length() > 256 || author.matches("(?s).*[\\x00-\\x1F\\x7F].*")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        // URL-safe Base64 restricts the cookie value to a fixed safe charset (Java 8 compatible)
        Cookie cookie = new Cookie("test3",
                Base64.getUrlEncoder().withoutPadding().encodeToString(author.getBytes(StandardCharsets.UTF_8)));
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
