package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
        // header values must match a strict allowlist and are rebuilt from a server side alphabet
        String test1 = SecurityUtil.safeHeaderValue(request.getParameter("test1"));
        String test2 = SecurityUtil.safeHeaderValue(request.getParameter("test2"));
        String author = SecurityUtil.safeCookieValue(request.getParameter("test3"));
        if (test1 == null && request.getParameter("test1") != null
                || test2 == null && request.getParameter("test2") != null
                || author == null && request.getParameter("test3") != null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (test1 != null) {
            response.addHeader("test1", test1);
        }
        if (test2 != null) {
            response.setHeader("test2", test2);
        }
        if (author != null) {
            Cookie cookie = new Cookie("test3", author);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(3600);
            response.addCookie(cookie);
        }
    }
}
