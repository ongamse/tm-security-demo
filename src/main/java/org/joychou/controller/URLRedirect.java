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
import java.util.HashMap;
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

    /** Allowlisted redirect targets keyed by a short identifier. */
    private static final Map<String, String> REDIRECT_ALLOWLIST;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("home", "/");
        m.put("login", "/login");
        m.put("index", "/index");
        m.put("dashboard", "/dashboard");
        m.put("test", "/urlRedirect/test");
        REDIRECT_ALLOWLIST = Collections.unmodifiableMap(m);
    }

    /** Default redirect when the requested key is not in the allowlist. */
    private static final String DEFAULT_REDIRECT = "/";

    /**
     * Safe redirect using a lookup table. User input selects from a fixed set
     * of known-safe destinations so no attacker-controlled data flows into the
     * redirect target.
     * <p>
     * http://localhost:8080/urlRedirect/redirect?url=home
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        String target = REDIRECT_ALLOWLIST.getOrDefault(url, DEFAULT_REDIRECT);
        return "redirect:" + target;
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", SecurityUtil.sanitizeHeaderValue(safeUrl));
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        String safeUrl = SecurityUtil.checkURL(url);
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
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(safeUrl);
    }
}
