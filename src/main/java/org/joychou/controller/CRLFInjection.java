package org.joychou.controller;

import org.joychou.util.WebUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.regex.Pattern;

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

        // whitelist validation first; reject (400) and write nothing on mismatch (fail closed)
        if (!isValid(raw1) || !isValid(raw2) || !isValidCookieValue(raw3)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // the written values are re-built from the server-side alphabet, not copied from the request
        String test1 = WebUtils.rebuildFromAllowed(raw1, ALLOWED_CHARS);
        String test2 = WebUtils.rebuildFromAllowed(raw2, ALLOWED_CHARS);
        String test3 = WebUtils.rebuildFromAllowed(raw3, COOKIE_ALLOWED_CHARS);

        if (test1 != null) {
            response.addHeader("test1", test1);
        }
        if (test2 != null) {
            response.setHeader("test2", test2);
        }
        if (test3 != null) {
            Cookie cookie = new Cookie("test3", test3);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);
        }
    }

    private static final String ALLOWED_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~ -";
    private static final Pattern SAFE_VALUE = Pattern.compile("[A-Za-z0-9._~ -]{0,100}");

    // cookie-safe alphabet: no space, no separators, no quotes
    private static final String COOKIE_ALLOWED_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-";
    private static final Pattern SAFE_COOKIE_VALUE = Pattern.compile("[A-Za-z0-9._~-]{0,100}");

    /** A missing parameter is valid (no cookie is written); otherwise the cookie whitelist regex must match. */
    private static boolean isValidCookieValue(String value) {
        return value == null || SAFE_COOKIE_VALUE.matcher(value).matches();
    }

    /** A missing parameter is valid (no header is written); otherwise the whitelist regex must match. */
    private static boolean isValid(String value) {
        return value == null || SAFE_VALUE.matcher(value).matches();
    }
}
