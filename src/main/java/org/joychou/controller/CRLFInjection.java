package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

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

    private static final String RECEIVED = "received";

    @RequestMapping("/safecode")
    public ResponseEntity<String> crlf(HttpServletRequest request, HttpServletResponse response) {
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        String author = request.getParameter("test3");
        // Reject CR/LF and other control characters (also url-encoded).
        if ((test1 != null && SecurityUtil.headerFilter(test1) == null) ||
                (test2 != null && SecurityUtil.headerFilter(test2) == null) ||
                (author != null && SecurityUtil.headerFilter(author) == null)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        // Request values are never written to response headers: they are echoed in the body only.
        if (author != null) {
            // Constant marker only; the request value is not placed in the cookie.
            Cookie cookie = new Cookie("test3", RECEIVED);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(3600);
            response.addCookie(cookie);
        }

        StringBuilder body = new StringBuilder();
        body.append("test1=").append(encode(test1)).append('\n');
        body.append("test2=").append(encode(test2)).append('\n');
        body.append("test3=").append(encode(author)).append('\n');

        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "text/plain; charset=UTF-8");
        headers.set("X-Content-Type-Options", "nosniff");
        return new ResponseEntity<>(body.toString(), headers, HttpStatus.OK);
    }

    /**
     * Entity-encode every char outside [A-Za-z0-9 ._-] as &#NN;.
     */
    private static String encode(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == ' ' || c == '.' || c == '_' || c == '-') {
                sb.append(c);
            } else {
                sb.append("&#").append((int) c).append(';');
            }
        }
        return sb.toString();
    }
}
