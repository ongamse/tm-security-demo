package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;

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
    public void crlf(HttpServletRequest request, HttpServletResponse response)
            throws UnsupportedEncodingException {
        // percent-encode so CR/LF can never reach the header line
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        String encTest1 = URLEncoder.encode(test1 == null ? "" : test1, "UTF-8");
        String encTest2 = URLEncoder.encode(test2 == null ? "" : test2, "UTF-8");
        response.addHeader("test1", encTest1);
        response.setHeader("test2", encTest2);
        String author = request.getParameter("test3");
        Cookie cookie = new Cookie("test3", author);
        response.addCookie(cookie);
    }
}
