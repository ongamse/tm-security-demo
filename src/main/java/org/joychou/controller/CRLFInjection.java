package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
    public void crlf(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        if (SecurityUtil.hasHeaderControlChars(test1) || SecurityUtil.hasHeaderControlChars(test2)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Illegal header value");
            return;
        }
        response.addHeader("test1", test1);
        response.setHeader("test2", test2);
        String author = request.getParameter("test3");
        Cookie cookie = new Cookie("test3", author);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
