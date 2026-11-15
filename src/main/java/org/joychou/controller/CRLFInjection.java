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
        // Header names are constants; values are written only if they pass the strict whitelist
        // and are then the re-built (not the raw request) value.
        String test1 = SecurityUtil.safeHeaderValue(request.getParameter("test1"));
        if (test1 != null) {
            response.addHeader("test1", test1);
        }
        String test2 = SecurityUtil.safeHeaderValue(request.getParameter("test2"));
        if (test2 != null) {
            response.setHeader("test2", test2);
        }
        String author = request.getParameter("test3");
        Cookie cookie = new Cookie("test3", author);
        response.addCookie(cookie);
    }
}
