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
    public String crlf(HttpServletRequest request, HttpServletResponse response) {
        String test1;
        String test2;
        String test3;
        try {
            test1 = SecurityUtil.rejectHeaderIfCRLF(request.getParameter("test1"));
            test2 = SecurityUtil.rejectHeaderIfCRLF(request.getParameter("test2"));
            test3 = SecurityUtil.rejectHeaderIfCRLF(request.getParameter("test3"));
        } catch (IllegalArgumentException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "Invalid input: header value must not contain CR or LF characters";
        }
        response.addHeader("test1", test1);
        response.setHeader("test2", test2);
        Cookie cookie = new Cookie("test3", test3);
        response.addCookie(cookie);
        return null;
    }
}
