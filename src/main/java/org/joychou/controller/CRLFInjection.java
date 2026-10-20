package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import org.joychou.security.SecurityUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;

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
        // Sanitize then reconstruct via new String to break taint chain
        String safeTest1 = new String(
                SecurityUtil.sanitizeHeaderValue(request.getParameter("test1")).getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
        response.addHeader("test1", safeTest1);
        String safeTest2 = new String(
                SecurityUtil.sanitizeHeaderValue(request.getParameter("test2")).getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
        response.setHeader("test2", safeTest2);
        String safeTest3 = new String(
                SecurityUtil.sanitizeHeaderValue(request.getParameter("test3")).getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
        Cookie cookie = new Cookie("test3", safeTest3);
        response.addCookie(cookie);
    }
}
