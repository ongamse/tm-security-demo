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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;

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
     * Exact (equals) host allowlist for absolute redirect targets. Never matched by suffix.
     */
    private static final Set<String> ALLOWED_REDIRECT_HOSTS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("joychou.org", "www.joychou.org", "test.joychou.org",
                    "joychou.com", "www.joychou.com", "localhost")));

    /**
     * Validate a redirect target and return the value to redirect to, or null to reject.
     * Rejects (never sanitises): null/empty, backslash, CR/LF or other control characters,
     * unparsable URIs, scheme-relative ("//host") targets, userinfo, non-http(s) schemes and any
     * host that is not exactly in {@link #ALLOWED_REDIRECT_HOSTS} (or blocked by the configured
     * block list). A target without a scheme must be a same-site path starting with a single '/'.
     * The returned value is the ASCII form of the parsed java.net.URI, not the raw request string.
     */
    private static String safeRedirectTarget(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c < 0x20 || c == 0x7f || c == '\\') {
                return null;
            }
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return null;
        }
        String scheme = uri.getScheme();
        if (scheme == null) {
            if (uri.getRawAuthority() != null || !url.startsWith("/") || url.startsWith("//")) {
                return null;
            }
            return uri.toASCIIString();
        }
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            return null;
        }
        if (uri.getRawUserInfo() != null) {
            return null;
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty() || !ALLOWED_REDIRECT_HOSTS.contains(host.toLowerCase())) {
            return null;
        }
        if (SecurityUtil.checkURL(url) == null) {
            return null;
        }
        return uri.toASCIIString();
    }

    /**
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url, HttpServletResponse response) throws IOException {
        String safeUrl = safeRedirectTarget(url);
        if (safeUrl == null) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "url forbidden");
            return null;
        }
        return "redirect:" + safeUrl;
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        if (!WebUtils.isSafeHeaderValue(url)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        String safeUrl = safeRedirectTarget(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", safeUrl);
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        String safeUrl = safeRedirectTarget(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(safeUrl); // 302 redirect
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
        String safeUrl = safeRedirectTarget(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(safeUrl);
    }
}
