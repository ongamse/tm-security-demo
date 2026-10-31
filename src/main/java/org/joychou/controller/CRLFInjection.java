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
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        // Reject CR, LF and any other control character outright, then URL-encode what is echoed.
        String author = request.getParameter("test3");
        if (!SecurityUtil.isValidHeaderValue(test1) || !SecurityUtil.isValidHeaderValue(test2)
                || !SecurityUtil.isValidHeaderValue(author)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (test1 != null) {
            response.addHeader("test1", SecurityUtil.encodeHeaderValue(test1));
        }
        if (test2 != null) {
            response.setHeader("test2", SecurityUtil.encodeHeaderValue(test2));
        }
        // URL-encoded so only [A-Za-z0-9%._~*+-] can reach the Set-Cookie header.
        Cookie cookie = new Cookie("test3", SecurityUtil.encodeHeaderValue(author));
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
