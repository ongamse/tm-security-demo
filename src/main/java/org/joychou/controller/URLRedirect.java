package org.joychou.controller;

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

import org.joychou.security.SafeUrl;
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

    /** Constant fallback redirect target (site root) for anything outside the closed set. */
    private static final String DEFAULT_TARGET = "/";

    /**
     * Closed set of trusted redirect targets (hosts mirror url/url_safe_domain.xml). Key: the exact
     * normalised host of an allowed target. Value: the complete constant redirect URL. Nothing from the
     * request is ever appended to the value.
     */
    private static final Map<String, String> TRUSTED_TARGETS;

    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("joychou.com", "https://joychou.com/");
        m.put("joychou.org", "https://joychou.org/");
        m.put("test.joychou.org", "https://test.joychou.org/");
        m.put("localhost", "http://localhost/");
        TRUSTED_TARGETS = Collections.unmodifiableMap(m);
    }

    /**
     * Resolve a request-supplied url to a constant redirect target. The request value is only used to
     * select an entry of the closed set; the returned string is always one of the map's own constants
     * (or {@link #DEFAULT_TARGET}).
     */
    private static String resolveTarget(String url) {
        String validated = SecurityUtil.checkRedirectURL(url);
        if (validated == null || validated.startsWith("/")) {
            return DEFAULT_TARGET; // disallowed or same-site path: fixed site root
        }
        SafeUrl parsed = SafeUrl.parse(validated);
        if (parsed == null) {
            return DEFAULT_TARGET;
        }
        String host = parsed.getHost();
        for (Map.Entry<String, String> e : TRUSTED_TARGETS.entrySet()) {
            if (e.getKey().equals(host)) {
                return e.getValue();
            }
        }
        return DEFAULT_TARGET;
    }

    /**
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        return "redirect:" + resolveTarget(url);
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        // the Location value is one of the closed set's constants, never request text
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", resolveTarget(url));
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        response.sendRedirect(resolveTarget(url)); // 302 redirect
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
        String url = request.getParameter("url");
        response.sendRedirect(resolveTarget(url));
    }
}
