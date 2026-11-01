package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * Java 1.7/1.8 no CRLF vulns (test in Java 1.7/1.8)
 *
 * @author JoyChou (joychou@joychou.org) @2018-01-03
 */
@Controller
@RequestMapping("/crlf")
public class CRLFInjection {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @RequestMapping("/safecode")
    @ResponseBody
    public void crlf(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        if (SecurityUtil.hasHeaderControlChars(test1) || SecurityUtil.hasHeaderControlChars(test2)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Illegal header value");
            return;
        }
        String author = request.getParameter("test3");
        if (SecurityUtil.hasHeaderControlChars(author)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Illegal cookie value");
            return;
        }
        // Request values are never copied into response headers or the cookie: the headers carry
        // fixed server-side constants and the cookie carries a server-generated random token.
        response.addHeader("test1", "ok");
        response.setHeader("test2", "ok");
        byte[] random = new byte[16];
        SECURE_RANDOM.nextBytes(random);
        StringBuilder token = new StringBuilder(random.length * 2);
        for (byte b : random) {
            token.append(String.format("%02x", b));
        }
        Cookie cookie = new Cookie("test3", token.toString());
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
