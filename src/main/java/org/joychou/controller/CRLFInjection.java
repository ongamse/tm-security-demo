package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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
    public void crlf(HttpServletRequest request, HttpServletResponse response)
            throws UnsupportedEncodingException {
        String test1 = SecurityUtil.cRlfFilter(request.getParameter("test1"));
        if (test1 != null) {
            response.addHeader("test1", URLEncoder.encode(test1, StandardCharsets.UTF_8.name()));
        }
        String test2 = SecurityUtil.cRlfFilter(request.getParameter("test2"));
        if (test2 != null) {
            response.setHeader("test2", URLEncoder.encode(test2, StandardCharsets.UTF_8.name()));
        }
        String author = SecurityUtil.cRlfFilter(request.getParameter("test3"));
        if (author != null) {
            // URL-encode so CR/LF and other reserved characters can never reach the Set-Cookie header
            author = URLEncoder.encode(author, StandardCharsets.UTF_8.name());
        }
        Cookie cookie = new Cookie("test3", author);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
