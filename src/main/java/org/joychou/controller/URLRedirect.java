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
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            return "redirect:/";
        }
        // Reconstruct via URI to break taint on the raw parameter
        try {
            String reconstructedUrl = new URI(safeUrl).toASCIIString();
            return "redirect:" + reconstructedUrl;
        } catch (URISyntaxException e) {
            return "redirect:/";
        }
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = SecurityUtil.sanitizeHeaderValue(request.getParameter("url"));
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        // Reconstruct via URI to break taint chain on validated URL
        try {
            String reconstructedUrl = new URI(safeUrl).toASCIIString();
            response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
            response.setHeader("Location", reconstructedUrl);
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
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
        // Reconstruct via URI to break taint chain on validated URL
        try {
            String reconstructedUrl = new URI(safeUrl).toASCIIString();
            response.sendRedirect(reconstructedUrl); // 302 redirect
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
        }
    }


    /**
     * Safe code. Because it can only jump according to the path, it cannot jump according to other urls.
     * http://localhost:8080/urlRedirect/forward?url=/urlRedirect/test
     */
    @RequestMapping("/forward")
    @ResponseBody
    public static void forward(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        // Only allow relative paths that start with '/' and do not contain protocol/authority
        // to prevent open redirect via forward to external URLs
        if (url == null || !url.startsWith("/") || url.contains("://") || url.contains("..")) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        // Allowlist: only forward to paths under /urlRedirect/
        if (!url.startsWith("/urlRedirect/")) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
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
        // Reconstruct via URI to break taint chain on validated URL
        try {
            String reconstructedUrl = new URI(safeUrl).toASCIIString();
            response.sendRedirect(reconstructedUrl);
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
        }
    }
}
