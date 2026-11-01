package org.joychou.controller;

import org.springframework.http.HttpHeaders;
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
import java.net.URI;

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
    @ResponseBody
    public void redirect(@RequestParam("url") String url, HttpServletResponse response) throws IOException {
        String target = SecurityUtil.safeRedirectTarget(url);
        if (target == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(target); // 302 redirect
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static ResponseEntity<String> setHeader(HttpServletRequest request) {
        String url = request.getParameter("url");
        String target = SecurityUtil.safeRedirectTarget(url);
        if (target == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("url forbidden");
        }
        // 301 redirect; target is a server-side constant from the fixed redirect table, set as a typed URI
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(target));
        return new ResponseEntity<String>(headers, HttpStatus.MOVED_PERMANENTLY);
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        String target = SecurityUtil.safeRedirectTarget(url);
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
        String target = SecurityUtil.safeRedirectTarget(url);
        if (target == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(target);
    }
}
