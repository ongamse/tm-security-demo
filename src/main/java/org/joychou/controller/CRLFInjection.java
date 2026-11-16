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
        // rebuild the header values from printable ASCII only (null/CR/LF/control chars are rejected)
        String safeTest1 = SecurityUtil.safeHeaderText(test1 == null ? "" : test1);
        String safeTest2 = SecurityUtil.safeHeaderText(test2 == null ? "" : test2);
        if (safeTest1 == null || safeTest2 == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        response.addHeader("test1", safeTest1);
        response.setHeader("test2", safeTest2);
        String author = request.getParameter("test3");
        Cookie cookie = new Cookie("test3", author);
        response.addCookie(cookie);
    }
}
