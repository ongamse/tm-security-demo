package org.joychou.controller;

import org.joychou.util.WebUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

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
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        // Reject (HTTP 400) instead of writing a header value that is not on the strict allowlist.
        if (!WebUtils.isSafeHeaderValue(test1) || !WebUtils.isSafeHeaderValue(test2)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (test1 != null) {
            response.addHeader("test1", URLEncoder.encode(test1, "UTF-8"));
        }
        if (test2 != null) {
            response.setHeader("test2", URLEncoder.encode(test2, "UTF-8"));
        }
        String author = request.getParameter("test3");
        Cookie cookie = new Cookie("test3", author);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
