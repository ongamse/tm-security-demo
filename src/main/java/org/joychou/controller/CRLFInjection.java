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
        String raw1 = request.getParameter("test1");
        String raw2 = request.getParameter("test2");
        String raw3 = request.getParameter("test3");

        String sanitized1 = SecurityUtil.sanitizeHeaderValue(raw1);
        String sanitized2 = SecurityUtil.sanitizeHeaderValue(raw2);
        String sanitized3 = SecurityUtil.sanitizeHeaderValue(raw3);

        if (sanitized1 != null) {
            response.addHeader("test1", sanitized1);
        }
        if (sanitized2 != null) {
            response.setHeader("test2", sanitized2);
        }
        if (sanitized3 != null) {
            Cookie cookie = new Cookie("test3", sanitized3);
            response.addCookie(cookie);
        }
    }
}
