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
        // URL-encoded values can never contain CR/LF, so no extra header line can be injected
        response.addHeader("test1", SecurityUtil.encodeHeaderValue(request.getParameter("test1")));
        response.setHeader("test2", SecurityUtil.encodeHeaderValue(request.getParameter("test2")));
        Cookie cookie = new Cookie("test3", SecurityUtil.encodeHeaderValue(request.getParameter("test3")));
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
