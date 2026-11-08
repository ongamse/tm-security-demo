package org.joychou.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.joychou.security.SecurityUtil;

/**
 * The vulnerability code and security code of Java url redirect.
 * The security code is checking whitelist of url redirect.
 *
 * @author JoyChou (joychou@joychou.org)
 * @version 2017.12.28
 */

@Controller
@RequestMapping("/urlRedirect")
public class URLRedirect {

    /**
     * Server-owned redirect targets (token -> constant same-site path or absolute url).
     * The request parameter is only used as a lookup key; the redirect always goes to the
     * constant value stored here, never to the request string.
     */
    private static final Map<String, String> REDIRECT_TARGETS;

    static {
        Map<String, String> targets = new LinkedHashMap<>();
        targets.put("home", "/");
        targets.put("login", "/login");
        targets.put("joychou", "https://www.joychou.org/");
        targets.put("joychou-com", "https://www.joychou.com/");
        targets.put("joychou-test", "https://test.joychou.org/");
        REDIRECT_TARGETS = Collections.unmodifiableMap(targets);
    }

    /**
     * Resolve a request value to a server-owned redirect target. The value matches either a
     * token (map key) or a full allowlisted target (map value), compared by exact equality.
     *
     * @param key untrusted lookup key
     * @return the constant redirect target from {@link #REDIRECT_TARGETS}, or null if unknown
     */
    private static String resolveRedirectTarget(String key) {
        if (key == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : REDIRECT_TARGETS.entrySet()) {
            if (entry.getKey().equals(key) || entry.getValue().equals(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public ResponseEntity<String> redirect(@RequestParam("url") String url) {
        // Location is rebuilt from validated components (fixed scheme, whitelisted chars).
        String safeUrl = SecurityUtil.safeRedirectLocation(url);
        if (safeUrl == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("url forbidden");
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", safeUrl)
                .build();
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        // The request value is only a lookup key; Location is the server-owned constant.
        String target = resolveRedirectTarget(request.getParameter("url"));
        if (target == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", target);
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // The request value is only a lookup key; the redirect goes to the server-owned constant.
        String target = resolveRedirectTarget(request.getParameter("url"));
        if (target == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(target); // 302 redirect
    }


    /**
     * Safe code. Because it can only jump according to the path, it cannot jump according to other urls.
     * http://localhost:8080/urlRedirect/forward?url=/urlRedirect/test
     */
    @RequestMapping("/forward")
    @ResponseBody
    public static void forward(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        RequestDispatcher rd = request.getRequestDispatcher(url);
        try {
            rd.forward(request, response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * Safe code of sendRedirect.
     * http://localhost:8080/urlRedirect/sendRedirect/sec?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect/sec")
    @ResponseBody
    public void sendRedirect_seccode(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // The request value is only a lookup key; the redirect goes to the server-owned constant.
        String target = resolveRedirectTarget(request.getParameter("url"));
        if (target == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(target);
    }
}
