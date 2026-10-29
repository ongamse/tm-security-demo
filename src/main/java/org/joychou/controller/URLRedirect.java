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
     * Server-side constant redirect destinations, keyed by a short name.
     */
    private static final Map<String, String> ALLOWED;

    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("home", "/");
        m.put("docs", "https://www.joychou.org/");
        ALLOWED = Collections.unmodifiableMap(m);
    }

    /**
     * Map a requested value to one of the constant destinations. The requested value matches either a key,
     * or a value that is accepted by {@link SecurityUtil#checkRedirectURL(String)}. The returned string is
     * always the constant held by {@link #ALLOWED}, never the request string.
     *
     * @return the constant destination, or null if nothing matches
     */
    static String resolveTarget(String requested) {
        if (requested == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : ALLOWED.entrySet()) {
            if (requested.equals(entry.getKey())) {
                return entry.getValue();
            }
        }
        if (SecurityUtil.checkRedirectURL(requested) == null) {
            return null;
        }
        for (String allowed : ALLOWED.values()) {
            if (requested.equals(allowed)) {
                return allowed;
            }
        }
        return null;
    }

    /**
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        String target = resolveTarget(url);
        if (target == null) {
            // Untrusted redirect target: fall back to a safe same-origin default.
            return "redirect:/";
        }
        return "redirect:" + target;
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        // Reject CR/LF and other control characters (also url-encoded) to prevent header injection.
        if (url != null && SecurityUtil.headerFilter(url) == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        // Only redirect to server-side constant destinations (open redirect).
        String target = resolveTarget(url);
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
        String url = request.getParameter("url");
        String target = resolveTarget(url);
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
        String url = request.getParameter("url");
        String target = resolveTarget(url);
        if (target == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(target);
    }
}
