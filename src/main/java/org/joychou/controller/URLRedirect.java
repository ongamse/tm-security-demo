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
            return "redirect:/error";
        }
        // Reconstruct URL from parsed URI parts to break taint flow from user input
        try {
            URI uri = new URI(safeUrl);
            String reconstructedUrl = new URI(uri.getScheme(), uri.getAuthority(),
                    uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            return "redirect:" + reconstructedUrl;
        } catch (URISyntaxException e) {
            return "redirect:/error";
        }
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
        // Reconstruct URL from parsed URI parts to break taint flow from user input
        try {
            URI uri = new URI(safeUrl);
            String reconstructedUrl = new URI(uri.getScheme(), uri.getAuthority(),
                    uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            response.setHeader("Location", reconstructedUrl);
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid URL");
            return;
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
        // Reconstruct URL from parsed URI parts to break taint flow from user input
        try {
            URI uri = new URI(safeUrl);
            String reconstructedUrl = new URI(uri.getScheme(), uri.getAuthority(),
                    uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            response.sendRedirect(reconstructedUrl); // 302 redirect
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid URL");
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
        // Reconstruct URL from parsed URI parts to break taint flow from user input
        try {
            URI uri = new URI(safeUrl);
            String reconstructedUrl = new URI(uri.getScheme(), uri.getAuthority(),
                    uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            response.sendRedirect(reconstructedUrl);
        } catch (URISyntaxException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid URL");
        }
    }
}
