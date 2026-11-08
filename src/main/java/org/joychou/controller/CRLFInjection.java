package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

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
        // Values are re-assembled from whitelisted characters only (max 128), never copied from the request.
        String test1 = SecurityUtil.whitelistRebuild(request.getParameter("test1"), 128);
        String test2 = SecurityUtil.whitelistRebuild(request.getParameter("test2"), 128);
        String author = SecurityUtil.cookieValueRebuild(request.getParameter("test3"), 128);
        if (test1 != null) {
            response.addHeader("test1", test1);
        }
        if (test2 != null) {
            response.setHeader("test2", test2);
        }
        if (author != null) {
            // Encode the already-rebuilt value so the cookie only ever contains base64url characters
            // [A-Za-z0-9_-]; the Set-Cookie header is built exclusively from this encoder output.
            String encodedAuthor = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(author.getBytes(StandardCharsets.UTF_8));
            response.addHeader("Set-Cookie", "test3=" + encodedAuthor
                    + "; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict");   // 1 HOUR
        }
    }
}
