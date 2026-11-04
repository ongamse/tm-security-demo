package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import org.joychou.util.WebUtils;

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
        String author = request.getParameter("test3");
        // Reject (never sanitise) anything that is not short printable ASCII, so no CR/LF/control/non-ASCII
        // character can reach a header or cookie.
        if (!WebUtils.isStrictHeaderValue(test1) || !WebUtils.isStrictHeaderValue(test2)
                || !WebUtils.isStrictCookieValue(author)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        response.addHeader("test1", test1);
        response.setHeader("test2", test2);

        // Servlet 3.1 Cookie has no SameSite attribute, so the cookie is written as a Set-Cookie header.
        // The name is a constant and the value matched [A-Za-z0-9_-]{1,256} above.
        StringBuilder setCookie = new StringBuilder("test3=").append(author)
                .append("; Path=/; HttpOnly; SameSite=Lax");
        if (request.isSecure()) {
            setCookie.append("; Secure");
        }
        response.addHeader("Set-Cookie", setCookie.toString());
    }
}
