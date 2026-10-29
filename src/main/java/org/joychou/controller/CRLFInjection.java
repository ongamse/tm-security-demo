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
        String author = request.getParameter("test3");
        // Reject CR/LF and other control characters (also url-encoded) to prevent header injection.
        if ((test1 != null && SecurityUtil.headerFilter(test1) == null) ||
                (test2 != null && SecurityUtil.headerFilter(test2) == null) ||
                (author != null && SecurityUtil.headerFilter(author) == null)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (test1 != null) {
            response.addHeader("test1", SecurityUtil.toHeaderSafe(test1));
        }
        if (test2 != null) {
            response.setHeader("test2", SecurityUtil.toHeaderSafe(test2));
        }
        if (author != null) {
            String safeAuthor = SecurityUtil.toHeaderSafe(author);
            Cookie cookie;
            try {
                cookie = new Cookie("test3", URLEncoder.encode(safeAuthor, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return;
            }
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(3600);
            response.addCookie(cookie);
        }
    }
}
